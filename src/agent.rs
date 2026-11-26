//! MQTT Gateway Agent implementation
//!
//! Implements the AgentHandlerV2 trait to process MQTT packets from WebSocket frames.

use crate::acl::{AclEvaluator, AclRequest};
use crate::auth::Authenticator;
use crate::config::{ConnectionContext, MqttAction, MqttGatewayConfig};
use crate::inspection::PayloadInspector;
use crate::mqtt::{
    check_packets, parse_packet, split_packets, MqttPacket, ParsedConnect, ParsedPublish,
    ParsedSubscribe,
};
use crate::qos::QosEnforcer;
use crate::ratelimit::RateLimiter;
use crate::retained::RetainedController;

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use dashmap::{DashMap, DashSet};
use parking_lot::{Mutex, RwLock};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::fingerprint::config_fingerprint;
use tracing::{debug, info, warn};
use zentinel_agent_protocol::v2::{
    AgentCapabilities, AgentFeatures, AgentHandlerV2, AgentLimits, DrainReason, HealthConfig,
    HealthStatus, MetricsReport, ShutdownReason,
};
use zentinel_agent_protocol::{
    AgentResponse, AuditMetadata, EventType, RequestCompleteEvent, RequestHeadersEvent,
    WebSocketDecision, WebSocketFrameEvent,
};

/// MQTT Gateway Agent
pub struct MqttGatewayAgent {
    /// Configuration
    config: Arc<RwLock<MqttGatewayConfig>>,
    /// Authenticator
    authenticator: Arc<RwLock<Authenticator>>,
    /// ACL evaluator
    acl: Arc<AclEvaluator>,
    /// Rate limiter
    rate_limiter: Arc<RateLimiter>,
    /// Payload inspector
    inspector: Arc<RwLock<PayloadInspector>>,
    /// QoS enforcer
    qos_enforcer: Arc<QosEnforcer>,
    /// Retained message controller
    retained_controller: Arc<RetainedController>,
    /// Connection contexts (keyed by correlation_id)
    connections: DashMap<String, ConnectionContext>,
    /// Connections (keyed by correlation_id) that are part-way through a
    /// binary WebSocket message: a binary frame without FIN has been seen and
    /// the FIN frame has not. Holds one entry per such connection, no data.
    /// A `DISCONNECT` does not remove an entry: it tracks the WebSocket
    /// message, which only a FIN frame ends, so the rest of a message that
    /// carries a `DISCONNECT` is still read.
    binary_messages: DashSet<String>,
    /// Metrics: total requests processed
    requests_total: AtomicU64,
    /// Metrics: total requests blocked
    requests_blocked: AtomicU64,
    /// Metrics: total authentication failures
    auth_failures: AtomicU64,
    /// Metrics: total ACL denials
    acl_denials: AtomicU64,
    /// Metrics: total rate limit hits
    rate_limit_hits: AtomicU64,
    /// Metrics: total inspection blocks
    inspection_blocks: AtomicU64,
    /// Configuration version
    config_version: Arc<RwLock<Option<String>>>,
    /// Canonical hash of the last configuration accepted from the proxy.
    /// The mutex also serialises configures arriving on several connections.
    config_hash: Mutex<Option<u64>>,
}

impl MqttGatewayAgent {
    /// Create a new MQTT Gateway agent with default configuration
    pub fn new() -> Result<Self> {
        Self::with_config(MqttGatewayConfig::default())
    }

    /// Create a new MQTT Gateway agent with the given configuration
    pub fn with_config(config: MqttGatewayConfig) -> Result<Self> {
        let authenticator = Authenticator::new(&config.auth)?;
        let acl = AclEvaluator::new(&config.acl).map_err(|e| anyhow::anyhow!("{}", e))?;
        let rate_limiter = RateLimiter::new(&config.rate_limit);
        let inspector = PayloadInspector::new(&config.inspection)?;
        let qos_enforcer = QosEnforcer::new(&config.qos);
        let retained_controller = RetainedController::new(&config.retained);

        Ok(Self {
            config: Arc::new(RwLock::new(config)),
            authenticator: Arc::new(RwLock::new(authenticator)),
            acl: Arc::new(acl),
            rate_limiter: Arc::new(rate_limiter),
            inspector: Arc::new(RwLock::new(inspector)),
            qos_enforcer: Arc::new(qos_enforcer),
            retained_controller: Arc::new(retained_controller),
            connections: DashMap::new(),
            binary_messages: DashSet::new(),
            requests_total: AtomicU64::new(0),
            requests_blocked: AtomicU64::new(0),
            auth_failures: AtomicU64::new(0),
            acl_denials: AtomicU64::new(0),
            rate_limit_hits: AtomicU64::new(0),
            inspection_blocks: AtomicU64::new(0),
            config_version: Arc::new(RwLock::new(None)),
            config_hash: Mutex::new(None),
        })
    }

    /// Reconfigure the agent with a complete configuration.
    ///
    /// Only the components whose section changed are rebuilt, so runtime
    /// state (rate-limit buckets, authenticated connections, compiled
    /// patterns) survives a reconfigure that leaves its settings alone.
    /// Everything that can fail is built before anything is replaced, so an
    /// error leaves the agent exactly as it was.
    pub fn reconfigure(&self, config: MqttGatewayConfig) -> Result<()> {
        let current = serde_json::to_value(&*self.config.read())?;
        let next = serde_json::to_value(&config)?;
        let changed: Vec<&str> = ["auth", "acl", "inspection", "rate-limit", "qos", "retained"]
            .into_iter()
            .filter(|section| current.get(*section) != next.get(*section))
            .collect();
        let has = |section: &str| changed.contains(&section);

        let authenticator = if has("auth") {
            Some(Authenticator::new(&config.auth)?)
        } else {
            None
        };
        if has("acl") {
            // Compile the rules once to validate them before swapping.
            AclEvaluator::new(&config.acl).map_err(|e| anyhow::anyhow!("{}", e))?;
        }
        let inspector = if has("inspection") {
            Some(PayloadInspector::new(&config.inspection)?)
        } else {
            None
        };

        if let Some(authenticator) = authenticator {
            *self.authenticator.write() = authenticator;
        }
        if has("acl") {
            self.acl
                .reconfigure(&config.acl)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
        }
        if has("rate-limit") {
            self.rate_limiter.reconfigure(&config.rate_limit);
        }
        if let Some(inspector) = inspector {
            *self.inspector.write() = inspector;
        }
        if has("qos") {
            self.qos_enforcer.reconfigure(&config.qos);
        }
        if has("retained") {
            self.retained_controller.reconfigure(&config.retained);
        }

        *self.config.write() = config;
        Ok(())
    }

    /// Apply a configuration received from the proxy. See
    /// [`AgentHandlerV2::on_configure`] for the rules.
    ///
    /// Returns the names of the settings that changed.
    pub fn apply_proxy_config(&self, raw: &serde_json::Value) -> Result<Vec<String>> {
        let hash = config_fingerprint(raw);
        let mut last = self.config_hash.lock();
        if *last == Some(hash) {
            return Ok(Vec::new());
        }
        let (next, changed) = self
            .config
            .read()
            .merged(raw)
            .map_err(|e| anyhow::anyhow!("invalid configuration: {e}"))?;
        if !changed.is_empty() {
            let auth_was_on = self.config.read().auth.enabled;
            if auth_was_on && !next.auth.enabled {
                warn!("Configuration turns MQTT authentication off (auth.enabled false)");
            }
            self.reconfigure(next)?;
        }
        *last = Some(hash);
        Ok(changed)
    }

    /// Process the MQTT packets in one WebSocket frame.
    ///
    /// A frame may carry several packets back to back. The whole frame is
    /// read before any packet in it is acted on, so a frame that cannot be
    /// read changes no state. Packets are decoded one at a time and not kept,
    /// so the memory used does not grow with the number of packets.
    /// The packets are then handled in order, and the first one that is not
    /// allowed decides the frame. The packets before it have been handled by
    /// then, so what they changed stays when the frame is refused: a
    /// `CONNECT` keeps its connection context and a `PUBLISH` keeps the rate
    /// limit it used, although the broker never receives them. In detect-only
    /// mode a refusal is logged and the packet allowed, so handling goes on
    /// with the next packet; a close still stops it. When every packet is
    /// allowed the frame is allowed, with the tags, rule IDs and reason codes
    /// of all of them.
    ///
    /// `fragment` is true when the frame is only part of a WebSocket message.
    fn process_mqtt_frame(
        &self,
        correlation_id: &str,
        client_ip: &str,
        data: &[u8],
        fragment: bool,
    ) -> AgentResponse {
        if let Err(e) = check_packets(data) {
            return self.unreadable_frame(&e, fragment);
        }

        let mut combined: Option<AgentResponse> = None;
        for bytes in split_packets(data) {
            let packet = match bytes.and_then(parse_packet) {
                Ok(packet) => packet,
                // Not reachable: check_packets decoded these same bytes. If it
                // ever happens the frame is refused rather than let through.
                Err(e) => return self.unreadable_frame(&e, fragment),
            };
            let response = self.process_mqtt_packet(correlation_id, client_ip, packet);
            if !matches!(
                response.websocket_decision,
                None | Some(WebSocketDecision::Allow)
            ) {
                return self.keep_message_whole(response, fragment, 1008, "Policy violation");
            }
            match combined.as_mut() {
                Some(combined) => merge_metadata(&mut combined.audit, response.audit),
                None => combined = Some(response),
            }
        }

        // A frame with no bytes holds no packet and has nothing to forward
        combined.unwrap_or_else(AgentResponse::websocket_allow)
    }

    /// Response for a frame whose bytes are not whole, readable MQTT packets.
    /// A packet that continues in another frame is not put back together.
    fn unreadable_frame(&self, error: &anyhow::Error, fragment: bool) -> AgentResponse {
        warn!(error = %error, "Failed to parse MQTT packet");
        let response = self.block_response("mqtt-parse-error", "Invalid MQTT packet");
        self.keep_message_whole(response, fragment, 1002, "Invalid MQTT packet")
    }

    /// Turn a drop into a close when the frame is only part of a WebSocket
    /// message: without one of its frames the broker would see a message that
    /// is cut short. The rule IDs and reason codes of the refusal are kept.
    fn keep_message_whole(
        &self,
        response: AgentResponse,
        fragment: bool,
        code: u16,
        reason: &str,
    ) -> AgentResponse {
        if !fragment || response.websocket_decision != Some(WebSocketDecision::Drop) {
            return response;
        }
        let mut response = response.with_websocket_decision(WebSocketDecision::Close {
            code,
            reason: reason.to_string(),
        });
        response.audit.tags.push("connection-closed".to_string());
        response
    }

    /// The connection's binary message, if one is open, has ended.
    fn end_binary_message(&self, id: &str) {
        // Looked at first because removing takes a write lock, and almost
        // every frame has nothing to remove
        if self.binary_messages.contains(id) {
            self.binary_messages.remove(id);
        }
    }

    /// Process one parsed MQTT packet
    fn process_mqtt_packet(
        &self,
        correlation_id: &str,
        client_ip: &str,
        packet: MqttPacket,
    ) -> AgentResponse {
        match packet {
            MqttPacket::Connect(connect) => {
                self.handle_connect(correlation_id, client_ip, &connect)
            }
            MqttPacket::Publish(publish) => self.handle_publish(correlation_id, &publish),
            MqttPacket::Subscribe(subscribe) => self.handle_subscribe(correlation_id, &subscribe),
            MqttPacket::Unsubscribe(unsubscribe) => {
                self.handle_unsubscribe(correlation_id, &unsubscribe.topics)
            }
            MqttPacket::Disconnect => self.handle_disconnect(correlation_id),
            MqttPacket::PingReq | MqttPacket::PingResp => {
                // Allow ping/pong
                AgentResponse::websocket_allow()
            }
            MqttPacket::Other(_) => {
                // Allow other packets (CONNACK, PUBACK, etc.) - these are from broker
                AgentResponse::websocket_allow()
            }
        }
    }

    /// Handle CONNECT packet
    fn handle_connect(
        &self,
        correlation_id: &str,
        client_ip: &str,
        connect: &ParsedConnect,
    ) -> AgentResponse {
        info!(
            client_id = %connect.client_id,
            client_ip = %client_ip,
            protocol_version = connect.protocol_version,
            "MQTT CONNECT"
        );

        // Authenticate
        let auth_result = self.authenticator.read().authenticate(connect, client_ip);

        if !auth_result.authenticated {
            warn!(
                client_id = %connect.client_id,
                reason = ?auth_result.reason,
                "Authentication failed"
            );
            self.auth_failures.fetch_add(1, Ordering::Relaxed);
            self.requests_blocked.fetch_add(1, Ordering::Relaxed);
            return self.close_connection(
                "auth-failed",
                auth_result
                    .reason
                    .as_deref()
                    .unwrap_or("Authentication failed"),
                0x05, // Not authorized
            );
        }

        // Create connection context
        let mut context = ConnectionContext {
            client_id: connect.client_id.clone(),
            username: connect.username.clone(),
            client_ip: client_ip.to_string(),
            protocol_version: connect.protocol_version,
            groups: Vec::new(),
            attributes: Default::default(),
        };

        // Apply auth result to context
        self.authenticator
            .read()
            .apply_to_context(&mut context, &auth_result);

        // Store context
        self.connections.insert(correlation_id.to_string(), context);

        debug!(client_id = %connect.client_id, "CONNECT allowed");
        AgentResponse::websocket_allow().with_audit(AuditMetadata {
            tags: vec![
                "mqtt".to_string(),
                "connect".to_string(),
                "success".to_string(),
            ],
            ..Default::default()
        })
    }

    /// Handle PUBLISH packet
    fn handle_publish(&self, correlation_id: &str, publish: &ParsedPublish) -> AgentResponse {
        let context = match self.connections.get(correlation_id) {
            Some(ctx) => ctx.clone(),
            None => {
                warn!("PUBLISH without CONNECT context");
                return self.close_connection("no-context", "No connection context", 0x01);
            }
        };

        debug!(
            client_id = %context.client_id,
            topic = %publish.topic,
            qos = publish.qos,
            retain = publish.retain,
            size = publish.payload.len(),
            "MQTT PUBLISH"
        );

        // ACL check
        let acl_result = self.acl.evaluate(&AclRequest {
            context: &context,
            topic: &publish.topic,
            action: MqttAction::Publish,
            qos: Some(publish.qos),
        });

        if !acl_result.allowed {
            info!(
                client_id = %context.client_id,
                topic = %publish.topic,
                rule = ?acl_result.rule_name,
                "PUBLISH denied by ACL"
            );
            self.acl_denials.fetch_add(1, Ordering::Relaxed);
            self.requests_blocked.fetch_add(1, Ordering::Relaxed);
            return self.drop_response("acl-denied", &acl_result.reason);
        }

        // Rate limit check
        let rate_result =
            self.rate_limiter
                .check_message(&context, &publish.topic, publish.payload.len());

        if !rate_result.allowed {
            info!(
                client_id = %context.client_id,
                limit = ?rate_result.exceeded_limit,
                "PUBLISH rate limited"
            );
            self.rate_limit_hits.fetch_add(1, Ordering::Relaxed);
            self.requests_blocked.fetch_add(1, Ordering::Relaxed);
            return self.drop_response(
                "rate-limited",
                &format!("Rate limit exceeded: {:?}", rate_result.exceeded_limit),
            );
        }

        // QoS check
        let qos_result = self.qos_enforcer.check(&publish.topic, publish.qos);
        if !qos_result.allowed {
            info!(
                client_id = %context.client_id,
                topic = %publish.topic,
                qos = publish.qos,
                "PUBLISH QoS denied"
            );
            return self.drop_response(
                "qos-denied",
                qos_result.reason.as_deref().unwrap_or("QoS not allowed"),
            );
        }

        // Retained message check
        let retained_result =
            self.retained_controller
                .check(&publish.topic, publish.payload.len(), publish.retain);

        if !retained_result.allowed {
            info!(
                client_id = %context.client_id,
                topic = %publish.topic,
                "Retained message denied"
            );
            return self.drop_response(
                "retained-denied",
                retained_result
                    .reason
                    .as_deref()
                    .unwrap_or("Retained not allowed"),
            );
        }

        // Payload inspection
        let inspection_result = self
            .inspector
            .read()
            .inspect(&publish.topic, &publish.payload);

        if !inspection_result.passed && inspection_result.should_block {
            let patterns: Vec<_> = inspection_result
                .detections
                .iter()
                .map(|d| d.pattern_id.clone())
                .collect();

            info!(
                client_id = %context.client_id,
                topic = %publish.topic,
                patterns = ?patterns,
                "PUBLISH blocked by inspection"
            );
            self.inspection_blocks.fetch_add(1, Ordering::Relaxed);
            self.requests_blocked.fetch_add(1, Ordering::Relaxed);
            return self.drop_response(
                "inspection-blocked",
                &format!("Malicious pattern detected: {:?}", patterns),
            );
        }

        // All checks passed
        debug!(client_id = %context.client_id, topic = %publish.topic, "PUBLISH allowed");
        AgentResponse::websocket_allow().with_audit(AuditMetadata {
            tags: vec!["mqtt".to_string(), "publish".to_string()],
            ..Default::default()
        })
    }

    /// Handle SUBSCRIBE packet
    fn handle_subscribe(&self, correlation_id: &str, subscribe: &ParsedSubscribe) -> AgentResponse {
        let context = match self.connections.get(correlation_id) {
            Some(ctx) => ctx.clone(),
            None => {
                warn!("SUBSCRIBE without CONNECT context");
                return self.close_connection("no-context", "No connection context", 0x01);
            }
        };

        debug!(
            client_id = %context.client_id,
            topics = ?subscribe.subscriptions.iter().map(|s| &s.topic_filter).collect::<Vec<_>>(),
            "MQTT SUBSCRIBE"
        );

        // Check ACL for each topic filter
        for sub in &subscribe.subscriptions {
            let acl_result = self.acl.evaluate(&AclRequest {
                context: &context,
                topic: &sub.topic_filter,
                action: MqttAction::Subscribe,
                qos: Some(sub.qos),
            });

            if !acl_result.allowed {
                info!(
                    client_id = %context.client_id,
                    topic = %sub.topic_filter,
                    rule = ?acl_result.rule_name,
                    "SUBSCRIBE denied by ACL"
                );
                self.acl_denials.fetch_add(1, Ordering::Relaxed);
                self.requests_blocked.fetch_add(1, Ordering::Relaxed);
                return self.drop_response("acl-denied", &acl_result.reason);
            }
        }

        debug!(client_id = %context.client_id, "SUBSCRIBE allowed");
        AgentResponse::websocket_allow().with_audit(AuditMetadata {
            tags: vec!["mqtt".to_string(), "subscribe".to_string()],
            ..Default::default()
        })
    }

    /// Handle UNSUBSCRIBE packet
    fn handle_unsubscribe(&self, correlation_id: &str, topics: &[String]) -> AgentResponse {
        let context = match self.connections.get(correlation_id) {
            Some(ctx) => ctx.clone(),
            None => {
                return AgentResponse::websocket_allow();
            }
        };

        debug!(
            client_id = %context.client_id,
            topics = ?topics,
            "MQTT UNSUBSCRIBE"
        );

        // Check ACL for unsubscribe (if you want to control this)
        for topic in topics {
            let acl_result = self.acl.evaluate(&AclRequest {
                context: &context,
                topic,
                action: MqttAction::Unsubscribe,
                qos: None,
            });

            if !acl_result.allowed {
                return self.drop_response("acl-denied", &acl_result.reason);
            }
        }

        AgentResponse::websocket_allow()
    }

    /// Handle DISCONNECT packet
    fn handle_disconnect(&self, correlation_id: &str) -> AgentResponse {
        if let Some((_, context)) = self.connections.remove(correlation_id) {
            debug!(client_id = %context.client_id, "MQTT DISCONNECT");
        }
        AgentResponse::websocket_allow()
    }

    /// Create a drop response (drop the frame)
    fn drop_response(&self, rule: &str, reason: &str) -> AgentResponse {
        let config = self.config.read();

        if config.general.block_mode {
            AgentResponse::websocket_drop().with_audit(AuditMetadata {
                tags: vec!["mqtt".to_string(), "blocked".to_string()],
                rule_ids: vec![rule.to_string()],
                reason_codes: vec![reason.to_string()],
                ..Default::default()
            })
        } else {
            // Detect-only mode: allow but log
            AgentResponse::websocket_allow().with_audit(AuditMetadata {
                tags: vec!["mqtt".to_string(), "detect-only".to_string()],
                rule_ids: vec![rule.to_string()],
                reason_codes: vec![reason.to_string()],
                ..Default::default()
            })
        }
    }

    /// Create a block response (for non-WebSocket errors)
    fn block_response(&self, rule: &str, reason: &str) -> AgentResponse {
        AgentResponse::websocket_drop().with_audit(AuditMetadata {
            tags: vec!["mqtt".to_string(), "error".to_string()],
            rule_ids: vec![rule.to_string()],
            reason_codes: vec![reason.to_string()],
            ..Default::default()
        })
    }

    /// Create a close connection response
    fn close_connection(&self, rule: &str, reason: &str, code: u16) -> AgentResponse {
        AgentResponse::websocket_close(code, reason.to_string()).with_audit(AuditMetadata {
            tags: vec!["mqtt".to_string(), "connection-closed".to_string()],
            rule_ids: vec![rule.to_string()],
            reason_codes: vec![reason.to_string()],
            ..Default::default()
        })
    }
}

/// Add the metadata of a later packet in a frame to that of the packets
/// before it, so that it grows with the kinds of refusal and not with the
/// number of packets. Tags are listed once. A rule ID and the reason code
/// at the same position form a pair, kept in order and added only if the pair
/// is not there yet, so that the n-th reason still belongs to the n-th rule.
/// This agent makes one of each per refusal; any left over when the lengths
/// differ are listed once, like tags. The higher confidence is kept, and
/// custom entries of the later packet replace those with the same key.
fn merge_metadata(metadata: &mut AuditMetadata, other: AuditMetadata) {
    // Every field is named, so a new one in AuditMetadata fails to compile here
    let AuditMetadata {
        tags,
        rule_ids,
        confidence,
        reason_codes,
        custom,
    } = other;
    for tag in tags {
        if !metadata.tags.contains(&tag) {
            metadata.tags.push(tag);
        }
    }
    let pairs = rule_ids.len().min(reason_codes.len());
    let mut rules = rule_ids.into_iter();
    let mut reasons = reason_codes.into_iter();
    for (rule, reason) in rules.by_ref().take(pairs).zip(reasons.by_ref().take(pairs)) {
        let known = metadata
            .rule_ids
            .iter()
            .zip(&metadata.reason_codes)
            .any(|(r, c)| *r == rule && *c == reason);
        if !known {
            metadata.rule_ids.push(rule);
            metadata.reason_codes.push(reason);
        }
    }
    for rule in rules {
        if !metadata.rule_ids.contains(&rule) {
            metadata.rule_ids.push(rule);
        }
    }
    for reason in reasons {
        if !metadata.reason_codes.contains(&reason) {
            metadata.reason_codes.push(reason);
        }
    }
    metadata.confidence = match (metadata.confidence, confidence) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (a, b) => a.or(b),
    };
    metadata.custom.extend(custom);
}

impl Default for MqttGatewayAgent {
    fn default() -> Self {
        Self::new().expect("Failed to create default MqttGatewayAgent")
    }
}

#[async_trait::async_trait]
impl AgentHandlerV2 for MqttGatewayAgent {
    /// Return agent capabilities for v2 protocol negotiation
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities {
            protocol_version: 2,
            agent_id: "mqtt-gateway".to_string(),
            name: "MQTT Gateway Agent".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            supported_events: vec![
                EventType::Configure,
                EventType::RequestHeaders,
                EventType::RequestComplete,
                EventType::WebSocketFrame,
            ],
            features: AgentFeatures {
                streaming_body: false,
                websocket: true,
                guardrails: false,
                config_push: true,
                metrics_export: true,
                concurrent_requests: 100,
                cancellation: true,
                flow_control: false,
                health_reporting: true,
            },
            limits: AgentLimits {
                max_body_size: 10 * 1024 * 1024, // 10MB
                max_concurrency: 100,
                preferred_chunk_size: 64 * 1024, // 64KB
                max_memory: None,
                max_processing_time_ms: Some(5000),
            },
            health: HealthConfig {
                report_interval_ms: 10_000,
                include_load_metrics: true,
                include_resource_metrics: false,
            },
        }
    }

    /// Handle configuration updates from the proxy
    /// The proxy sends the agent's `config { }` block on every connection
    /// (each pooled connection, and every reconnect), so this is idempotent:
    /// a block identical to the last one accepted, or one that changes no
    /// setting, leaves all state alone. The block overlays the running
    /// configuration (absent keys keep their value); unknown keys are
    /// rejected. The configuration itself is never logged, since it may hold
    /// secrets (JWT secrets, provider headers); its hash and the changed
    /// setting names are.
    async fn on_configure(&self, config: serde_json::Value, version: Option<String>) -> bool {
        let hash = format!("{:016x}", config_fingerprint(&config));
        match self.apply_proxy_config(&config) {
            Ok(changed) => {
                if changed.is_empty() {
                    debug!(version = ?version, config_hash = %hash, "Configuration unchanged");
                } else {
                    info!(
                        version = ?version,
                        config_hash = %hash,
                        changed = ?changed,
                        "Configuration applied"
                    );
                }
                if let Some(v) = version {
                    *self.config_version.write() = Some(v);
                }
                true
            }
            Err(e) => {
                warn!(version = ?version, config_hash = %hash, error = %e, "Configuration rejected");
                false
            }
        }
    }

    async fn on_request_headers(&self, _event: RequestHeadersEvent) -> AgentResponse {
        // We only handle WebSocket frames
        AgentResponse::default_allow()
    }

    async fn on_websocket_frame(&self, event: WebSocketFrameEvent) -> AgentResponse {
        self.requests_total.fetch_add(1, Ordering::Relaxed);

        // Only inspect client-to-server frames
        if !event.client_to_server {
            return AgentResponse::websocket_allow();
        }

        // Only binary messages carry MQTT (MQTT over WebSocket). A `binary`
        // frame starts one, and `continuation` frames carry on the message
        // started last, so they are inspected only while that one is binary.
        let id = &event.correlation_id;
        let fragment = match event.opcode.as_str() {
            "binary" => {
                if event.fin {
                    self.end_binary_message(id);
                } else {
                    self.binary_messages.insert(id.clone());
                }
                !event.fin
            }
            "continuation" => {
                if !self.binary_messages.contains(id) {
                    return AgentResponse::websocket_allow();
                }
                if event.fin {
                    self.end_binary_message(id);
                }
                true
            }
            "text" => {
                self.end_binary_message(id);
                return AgentResponse::websocket_allow();
            }
            // Control frames can sit in the middle of a message and do not
            // change what it is
            _ => return AgentResponse::websocket_allow(),
        };

        // Decode base64 payload
        let data = match BASE64.decode(&event.data) {
            Ok(d) => d,
            Err(e) => {
                warn!(error = %e, "Failed to decode WebSocket frame data");
                return AgentResponse::websocket_allow();
            }
        };

        // Log if configured
        if self.config.read().general.log_packets {
            debug!(
                correlation_id = %event.correlation_id,
                frame_index = event.frame_index,
                size = data.len(),
                "Processing MQTT frame"
            );
        }

        // Process the MQTT packets
        let response = self.process_mqtt_frame(id, &event.client_ip, &data, fragment);
        if matches!(
            response.websocket_decision,
            Some(WebSocketDecision::Close { .. })
        ) {
            self.end_binary_message(id);
        }
        response
    }

    /// The proxy sends this when a WebSocket connection ends, as it does for
    /// any request, whatever `events` the agent block lists. The state kept
    /// for the connection is dropped, since a `DISCONNECT` may never have
    /// been seen.
    async fn on_request_complete(&self, event: RequestCompleteEvent) -> AgentResponse {
        self.connections.remove(&event.correlation_id);
        self.end_binary_message(&event.correlation_id);
        AgentResponse::default_allow()
    }

    /// Return current health status
    fn health_status(&self) -> HealthStatus {
        let connections = self.connections.len() as u32;
        let requests = self.requests_total.load(Ordering::Relaxed);
        let blocked = self.requests_blocked.load(Ordering::Relaxed);

        let mut status = HealthStatus::healthy("mqtt-gateway");
        status.load = Some(zentinel_agent_protocol::v2::LoadMetrics {
            in_flight: connections,
            queue_depth: 0,
            avg_latency_ms: 0.0,
            p50_latency_ms: 0.0,
            p95_latency_ms: 0.0,
            p99_latency_ms: 0.0,
            requests_processed: requests,
            requests_rejected: blocked,
            requests_timed_out: 0,
        });
        status
    }

    /// Return metrics report for export
    fn metrics_report(&self) -> Option<MetricsReport> {
        use zentinel_agent_protocol::v2::{CounterMetric, GaugeMetric};

        let mut report = MetricsReport::new("mqtt-gateway", 10_000);

        report.counters.push(CounterMetric::new(
            "mqtt_gateway_requests_total",
            self.requests_total.load(Ordering::Relaxed),
        ));
        report.counters.push(CounterMetric::new(
            "mqtt_gateway_requests_blocked_total",
            self.requests_blocked.load(Ordering::Relaxed),
        ));
        report.counters.push(CounterMetric::new(
            "mqtt_gateway_auth_failures_total",
            self.auth_failures.load(Ordering::Relaxed),
        ));
        report.counters.push(CounterMetric::new(
            "mqtt_gateway_acl_denials_total",
            self.acl_denials.load(Ordering::Relaxed),
        ));
        report.counters.push(CounterMetric::new(
            "mqtt_gateway_rate_limit_hits_total",
            self.rate_limit_hits.load(Ordering::Relaxed),
        ));
        report.counters.push(CounterMetric::new(
            "mqtt_gateway_inspection_blocks_total",
            self.inspection_blocks.load(Ordering::Relaxed),
        ));
        report.gauges.push(GaugeMetric::new(
            "mqtt_gateway_active_connections",
            self.connections.len() as f64,
        ));

        Some(report)
    }

    /// Handle shutdown request from proxy
    async fn on_shutdown(&self, reason: ShutdownReason, grace_period_ms: u64) {
        info!(
            reason = ?reason,
            grace_period_ms = grace_period_ms,
            "Received shutdown request"
        );
        // Clear connection contexts on shutdown
        self.connections.clear();
        self.binary_messages.clear();
    }

    /// Handle drain request from proxy
    async fn on_drain(&self, duration_ms: u64, reason: DrainReason) {
        info!(
            duration_ms = duration_ms,
            reason = ?reason,
            "Received drain request"
        );
        // In drain mode, we continue processing existing connections
        // but the proxy will stop sending new ones
    }
}

#[cfg(test)]
mod configure_tests {
    use super::*;
    use crate::config::{RateLimit, RateLimitConfig};
    use serde_json::json;

    fn client() -> ConnectionContext {
        ConnectionContext {
            client_id: "sensor-1".to_string(),
            client_ip: "127.0.0.1".to_string(),
            protocol_version: 4,
            ..Default::default()
        }
    }

    fn limited_agent() -> MqttGatewayAgent {
        let config = MqttGatewayConfig {
            rate_limit: RateLimitConfig {
                enabled: true,
                per_client: Some(RateLimit {
                    messages_per_second: 1,
                    bytes_per_second: 0,
                    burst: 3,
                }),
                ..Default::default()
            },
            ..Default::default()
        };
        MqttGatewayAgent::with_config(config).unwrap()
    }

    fn allowed(agent: &MqttGatewayAgent) -> bool {
        agent
            .rate_limiter
            .check_message(&client(), "sensors/1/data", 10)
            .allowed
    }

    #[tokio::test]
    async fn identical_configure_keeps_rate_limit_buckets() {
        let agent = limited_agent();
        let block = json!({
            "rate-limit": {
                "enabled": true,
                "per-client": {"messages-per-second": 1, "burst": 3}
            }
        });
        assert!(agent.on_configure(block.clone(), None).await);
        for _ in 0..3 {
            assert!(allowed(&agent));
        }
        // Another pooled connection, or a reconnect, sends the same block.
        assert!(agent.on_configure(block.clone(), None).await);
        assert!(
            !allowed(&agent),
            "a repeated configure must not refill the bucket"
        );
    }

    #[tokio::test]
    async fn unrelated_change_keeps_rate_limit_buckets() {
        let agent = limited_agent();
        for _ in 0..3 {
            assert!(allowed(&agent));
        }
        assert!(
            agent
                .on_configure(json!({"qos": {"max-qos": 1}}), None)
                .await
        );
        assert!(!allowed(&agent));
        // Changing the limit itself does rebuild the per-client buckets.
        let raised = json!({"rate-limit": {"per-client": {"messages-per-second": 1, "burst": 5}}});
        assert!(agent.on_configure(raised, None).await);
        assert!(allowed(&agent));
    }

    fn file_config() -> MqttGatewayConfig {
        MqttGatewayConfig::from_json(&json!({
            "auth": {
                "enabled": true,
                "providers": [{"type": "jwt", "secret": "file-secret"}]
            },
            "acl": {
                "default-action": "allow",
                "rules": [{"name": "deny-sys", "topics": ["$SYS/#"], "decision": "deny"}]
            },
            "inspection": {"enabled": true, "patterns": {"sqli": true}}
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn partial_configure_keeps_file_values() {
        let agent = MqttGatewayAgent::with_config(file_config()).unwrap();
        // A block that does not mention auth, acl or inspection.
        assert!(
            agent
                .on_configure(json!({"qos": {"enabled": true, "max-qos": 1}}), None)
                .await
        );
        {
            let config = agent.config.read();
            assert!(config.auth.enabled, "omitting auth must not turn it off");
            assert_eq!(config.auth.providers.len(), 1);
            assert_eq!(config.acl.rules.len(), 1);
            assert!(config.inspection.enabled);
            assert!(config.inspection.patterns.sqli);
            assert!(config.qos.enabled);
            assert_eq!(config.qos.max_qos, 1);
        }
        // Nested merge: one field of a section leaves its siblings alone.
        assert!(
            agent
                .on_configure(json!({"auth": {"allow-anonymous": true}}), None)
                .await
        );
        let config = agent.config.read();
        assert!(config.auth.enabled);
        assert!(config.auth.allow_anonymous);
        assert_eq!(config.auth.providers.len(), 1);
    }

    #[tokio::test]
    async fn providers_without_enabled_turn_auth_on() {
        let agent = MqttGatewayAgent::new().unwrap();
        assert!(!agent.config.read().auth.enabled);
        // What a KDL `auth { providers { type "jwt"; secret "s" } }` sends.
        let block = json!({"auth": {"providers": {"type": "jwt", "secret": "s"}}});
        assert!(agent.on_configure(block, None).await);
        assert!(agent.config.read().auth.enabled);
        assert_eq!(agent.config.read().auth.providers.len(), 1);
        // Only an explicit false turns it off.
        assert!(
            agent
                .on_configure(json!({"auth": {"enabled": false}}), None)
                .await
        );
        assert!(!agent.config.read().auth.enabled);
    }

    #[tokio::test]
    async fn unknown_keys_are_rejected_and_nothing_changes() {
        let agent = MqttGatewayAgent::with_config(file_config()).unwrap();
        for bad in [
            json!({"auht": {"enabled": false}}),
            json!({"auth": {"enable": false}}),
            json!({"rate-limit": {"per-clinet": {"messages-per-second": 1}}}),
            json!({"auth": {"providers": [{"type": "jwt", "secrte": "x"}]}}),
            json!({"acl": {"rules": [{"name": "r", "topics": "a/#", "decision": "allow", "prio": 1}]}}),
            json!([1, 2]),
        ] {
            assert!(
                !agent.on_configure(bad.clone(), None).await,
                "{bad} accepted"
            );
        }
        let config = agent.config.read();
        assert!(config.auth.enabled);
        assert_eq!(config.acl.rules.len(), 1);
        assert_eq!(config.acl.rules[0].name, "deny-sys");
    }

    #[tokio::test]
    async fn single_value_lists_from_kdl() {
        let agent = MqttGatewayAgent::new().unwrap();
        let block = json!({"retained": {"enabled": true, "allowed-topics": "config/#"}});
        assert!(agent.on_configure(block, None).await);
        assert_eq!(
            agent.config.read().retained.allowed_topics,
            vec!["config/#".to_string()]
        );
    }
}

#[cfg(test)]
mod frame_tests {
    use super::*;
    use mqttrs::{encode_slice, Connect, Packet, Protocol, Publish, QosPid};
    use serde_json::json;

    const ALLOWED_TOPIC: &str = "sensors/a/data";
    const DENIED_TOPIC: &str = "internal/a";
    const RESTRICTED_TOPIC: &str = "restricted/a";

    fn encode(packet: Packet) -> Vec<u8> {
        let mut buf = [0u8; 256];
        let len = encode_slice(&packet, &mut buf).unwrap();
        buf[..len].to_vec()
    }

    fn connect_packet() -> Vec<u8> {
        encode(Packet::Connect(Connect {
            protocol: Protocol::MQTT311,
            keep_alive: 30,
            client_id: "client-a",
            clean_session: true,
            last_will: None,
            username: None,
            password: None,
        }))
    }

    fn publish_packet(topic: &str, payload: &[u8]) -> Vec<u8> {
        encode(Packet::Publish(Publish {
            dup: false,
            qospid: QosPid::AtMostOnce,
            retain: false,
            topic_name: topic,
            payload,
        }))
    }

    fn allowed_publish() -> Vec<u8> {
        publish_packet(ALLOWED_TOPIC, b"hello")
    }

    fn acl_denied_publish() -> Vec<u8> {
        publish_packet(DENIED_TOPIC, b"hello")
    }

    /// Refused by an ACL rule that names it, not by the default.
    fn restricted_publish() -> Vec<u8> {
        publish_packet(RESTRICTED_TOPIC, b"hello")
    }

    /// Allowed by the ACL, refused by the payload size limit (16 bytes).
    fn oversized_publish() -> Vec<u8> {
        publish_packet(ALLOWED_TOPIC, b"a payload over the limit")
    }

    fn disconnect_packet() -> Vec<u8> {
        encode(Packet::Disconnect)
    }

    fn frame(opcode: &str, fin: bool, data: &[u8]) -> WebSocketFrameEvent {
        WebSocketFrameEvent {
            correlation_id: "c1".to_string(),
            opcode: opcode.to_string(),
            data: BASE64.encode(data),
            client_to_server: true,
            frame_index: 0,
            fin,
            route_id: None,
            client_ip: "192.0.2.1".to_string(),
        }
    }

    fn binary(data: &[u8]) -> WebSocketFrameEvent {
        frame("binary", true, data)
    }

    fn settings(block_mode: bool) -> serde_json::Value {
        json!({
            "acl": {
                "default-action": "deny",
                "rules": [
                    {"name": "allow-sensors", "topics": ["sensors/#"], "decision": "allow"},
                    {"name": "deny-restricted", "topics": ["restricted/#"], "decision": "deny"}
                ]
            },
            "inspection": {"enabled": true, "max-payload-size": 16},
            "general": {"block-mode": block_mode}
        })
    }

    fn agent() -> MqttGatewayAgent {
        let config = MqttGatewayConfig::from_json(&settings(true)).unwrap();
        MqttGatewayAgent::with_config(config).unwrap()
    }

    fn detect_only_agent() -> MqttGatewayAgent {
        let config = MqttGatewayConfig::from_json(&settings(false)).unwrap();
        MqttGatewayAgent::with_config(config).unwrap()
    }

    /// An agent that allows two messages per client and then limits it.
    fn rate_limited_agent() -> MqttGatewayAgent {
        let mut value = settings(true);
        value["rate-limit"] = json!({
            "enabled": true,
            "per-client": {"messages-per-second": 1, "burst": 2}
        });
        MqttGatewayAgent::with_config(MqttGatewayConfig::from_json(&value).unwrap()).unwrap()
    }

    /// An agent that has seen an allowed CONNECT for correlation ID `c1`.
    async fn connected(agent: MqttGatewayAgent) -> MqttGatewayAgent {
        let response = agent.on_websocket_frame(binary(&connect_packet())).await;
        assert_eq!(outcome(&response), Expect::Allow);
        agent
    }

    /// The decision on a frame.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Expect {
        Allow,
        Drop,
        Close(u16),
    }

    fn outcome(response: &AgentResponse) -> Expect {
        match &response.websocket_decision {
            Some(WebSocketDecision::Allow) => Expect::Allow,
            Some(WebSocketDecision::Drop) => Expect::Drop,
            Some(WebSocketDecision::Close { code, .. }) => Expect::Close(*code),
            None => panic!("the response has no WebSocket decision"),
        }
    }

    fn rule_ids(response: &AgentResponse) -> Vec<&str> {
        response.audit.rule_ids.iter().map(String::as_str).collect()
    }

    fn request_complete() -> RequestCompleteEvent {
        RequestCompleteEvent {
            correlation_id: "c1".to_string(),
            status: 101,
            duration_ms: 1000,
            request_body_size: 0,
            response_body_size: 0,
            upstream_attempts: 1,
            error: None,
        }
    }

    // ---- several packets in one frame ----

    #[tokio::test]
    async fn frame_with_a_refused_packet_is_dropped_wherever_the_packet_is() {
        // (case, connect first, the packets of the frame, the rule that refuses)
        let cases = [
            (
                "CONNECT then ACL-refused PUBLISH",
                false,
                vec![connect_packet(), acl_denied_publish()],
                "acl-denied",
            ),
            (
                "allowed then ACL-refused PUBLISH",
                true,
                vec![allowed_publish(), acl_denied_publish()],
                "acl-denied",
            ),
            (
                "ACL-refused then allowed PUBLISH",
                true,
                vec![acl_denied_publish(), allowed_publish()],
                "acl-denied",
            ),
            (
                "allowed then payload-refused PUBLISH",
                true,
                vec![allowed_publish(), oversized_publish()],
                "inspection-blocked",
            ),
            (
                "payload-refused then allowed PUBLISH",
                true,
                vec![oversized_publish(), allowed_publish()],
                "inspection-blocked",
            ),
            (
                "two allowed then ACL-refused PUBLISH",
                true,
                vec![allowed_publish(), allowed_publish(), acl_denied_publish()],
                "acl-denied",
            ),
            (
                "the first refusal decides",
                true,
                vec![acl_denied_publish(), oversized_publish()],
                "acl-denied",
            ),
        ];
        for (case, connect_first, packets, rule) in cases {
            let agent = if connect_first {
                connected(agent()).await
            } else {
                agent()
            };

            let response = agent.on_websocket_frame(binary(&packets.concat())).await;

            assert_eq!(outcome(&response), Expect::Drop, "{case}");
            assert_eq!(rule_ids(&response), vec![rule], "{case}");
        }
    }

    #[tokio::test]
    async fn unreadable_frame_is_dropped_and_closes_a_fragmented_message() {
        let mut cut_off = allowed_publish();
        cut_off.pop();
        let cases = [
            (
                "packet type 0 after a PUBLISH",
                [allowed_publish(), vec![0x00, 0x00]].concat(),
            ),
            (
                "fixed header cut off before its length",
                [allowed_publish(), vec![0x30]].concat(),
            ),
            (
                "remaining length that never ends",
                [allowed_publish(), vec![0x30, 0x80, 0x80, 0x80, 0x80]].concat(),
            ),
            (
                "remaining length cut off",
                [allowed_publish(), vec![0x30, 0x80]].concat(),
            ),
            (
                "PUBLISH cut off at the end of the frame",
                [allowed_publish(), cut_off].concat(),
            ),
            (
                "remaining length longer than the rest of the frame",
                [allowed_publish(), vec![0x30, 0x05, 0x00]].concat(),
            ),
            (
                "remaining length of 0 spelled in two bytes",
                [allowed_publish(), vec![0x30, 0x80, 0x00]].concat(),
            ),
            (
                "PUBACK shorter than its fields",
                [allowed_publish(), vec![0x40, 0x00]].concat(),
            ),
            (
                "CONNACK shorter than its fields after a refused PUBLISH",
                [acl_denied_publish(), vec![0x20, 0x00]].concat(),
            ),
            ("SUBSCRIBE shorter than its fields", vec![0x82, 0x00]),
            (
                "front half of a PUBLISH that continues in the next frame",
                allowed_publish()[..allowed_publish().len() / 2].to_vec(),
            ),
            (
                "front half of a CONNECT that continues in the next frame",
                connect_packet()[..connect_packet().len() / 2].to_vec(),
            ),
            (
                "CONNECT shorter than its fields",
                vec![0x10, 0x06, 0x00, 0x04, b'M', b'Q', b'T', b'T'],
            ),
        ];
        for (case, data) in cases {
            let agent = connected(agent()).await;

            let whole = agent.on_websocket_frame(binary(&data)).await;
            assert_eq!(outcome(&whole), Expect::Drop, "{case}");
            assert_eq!(rule_ids(&whole), vec!["mqtt-parse-error"], "{case}");

            let fragment = agent
                .on_websocket_frame(frame("binary", false, &data))
                .await;
            assert_eq!(outcome(&fragment), Expect::Close(1002), "{case}");
            assert_eq!(rule_ids(&fragment), vec!["mqtt-parse-error"], "{case}");
        }
    }

    #[tokio::test]
    async fn unreadable_frame_acts_on_none_of_its_packets() {
        for unreadable in [vec![0x00, 0x00], vec![0x40, 0x00]] {
            let agent = agent();
            let data = [connect_packet(), unreadable.clone()].concat();

            let response = agent.on_websocket_frame(binary(&data)).await;

            assert_eq!(outcome(&response), Expect::Drop, "{unreadable:?}");
            assert!(
                agent.connections.is_empty(),
                "the CONNECT in a dropped frame must not create a connection"
            );
        }
    }

    #[tokio::test]
    async fn frame_with_two_allowed_packets_is_allowed_with_the_tags_of_both() {
        let agent = agent();
        let data = [connect_packet(), allowed_publish()].concat();

        let response = agent.on_websocket_frame(binary(&data)).await;

        assert_eq!(outcome(&response), Expect::Allow);
        assert_eq!(
            response.audit.tags,
            vec!["mqtt", "connect", "success", "publish"]
        );
        assert!(response.audit.rule_ids.is_empty());

        let data = [allowed_publish(), allowed_publish()].concat();
        let response = agent.on_websocket_frame(binary(&data)).await;

        assert_eq!(outcome(&response), Expect::Allow);
        assert_eq!(response.audit.tags, vec!["mqtt", "publish"]);
    }

    #[tokio::test]
    async fn packets_in_a_frame_are_handled_in_order() {
        let agent = agent();
        // The DISCONNECT removes the connection the PUBLISH would need.
        let data = [connect_packet(), disconnect_packet(), allowed_publish()].concat();

        let response = agent.on_websocket_frame(binary(&data)).await;

        assert_eq!(outcome(&response), Expect::Close(0x01));
        assert_eq!(rule_ids(&response), vec!["no-context"]);
    }

    #[tokio::test]
    async fn refused_frame_keeps_what_the_packets_before_the_refusal_set() {
        let agent = agent();
        let data = [connect_packet(), acl_denied_publish()].concat();

        let refused = agent.on_websocket_frame(binary(&data)).await;
        assert_eq!(outcome(&refused), Expect::Drop);

        // The CONNECT was handled, although the broker never receives it.
        let next = agent.on_websocket_frame(binary(&allowed_publish())).await;
        assert_eq!(outcome(&next), Expect::Allow);
    }

    #[tokio::test]
    async fn refused_frame_keeps_the_rate_limit_the_packets_before_the_refusal_used() {
        // The limiter refills in real time, at one message per second or
        // faster (it has no slower setting), so this relies on the two frames
        // following each other within a second.
        let agent = connected(rate_limited_agent()).await;
        // Two messages are allowed per client: both are spent by this frame.
        let data = [allowed_publish(), oversized_publish()].concat();

        let refused = agent.on_websocket_frame(binary(&data)).await;
        assert_eq!(outcome(&refused), Expect::Drop);
        assert_eq!(rule_ids(&refused), vec!["inspection-blocked"]);

        let next = agent.on_websocket_frame(binary(&allowed_publish())).await;
        assert_eq!(outcome(&next), Expect::Drop);
        assert_eq!(rule_ids(&next), vec!["rate-limited"]);
    }

    #[tokio::test]
    async fn empty_frame_is_allowed() {
        let agent = agent();

        let response = agent.on_websocket_frame(binary(&[])).await;

        assert_eq!(outcome(&response), Expect::Allow);
    }

    // ---- detect-only mode ----

    #[tokio::test]
    async fn detect_only_frame_handles_every_packet_and_allows() {
        let agent = connected(detect_only_agent()).await;
        for data in [
            [allowed_publish(), acl_denied_publish()].concat(),
            [acl_denied_publish(), allowed_publish()].concat(),
        ] {
            let response = agent.on_websocket_frame(binary(&data)).await;

            assert_eq!(outcome(&response), Expect::Allow);
            assert!(response.audit.tags.contains(&"detect-only".to_string()));
            assert_eq!(rule_ids(&response), vec!["acl-denied"]);
        }
    }

    #[tokio::test]
    async fn detect_only_frame_lists_the_same_refusal_once() {
        let agent = connected(detect_only_agent()).await;
        let data = [
            acl_denied_publish(),
            acl_denied_publish(),
            acl_denied_publish(),
        ]
        .concat();

        let response = agent.on_websocket_frame(binary(&data)).await;

        assert_eq!(outcome(&response), Expect::Allow);
        assert_eq!(rule_ids(&response), vec!["acl-denied"]);
        assert_eq!(response.audit.reason_codes.len(), 1);
        assert_eq!(response.audit.tags, vec!["mqtt", "detect-only"]);
    }

    #[tokio::test]
    async fn detect_only_frame_lists_each_kind_of_refusal_in_order() {
        let agent = connected(detect_only_agent()).await;
        let data = [
            acl_denied_publish(),
            allowed_publish(),
            oversized_publish(),
            restricted_publish(),
            acl_denied_publish(),
            oversized_publish(),
        ]
        .concat();

        let response = agent.on_websocket_frame(binary(&data)).await;

        assert_eq!(outcome(&response), Expect::Allow);
        // The same rule ID with another reason is another pair, and the n-th
        // reason still belongs to the n-th rule.
        assert_eq!(
            rule_ids(&response),
            vec!["acl-denied", "inspection-blocked", "acl-denied"]
        );
        let reasons = &response.audit.reason_codes;
        assert_eq!(reasons.len(), 3);
        assert_eq!(reasons[0], "No matching rule, default deny");
        assert!(reasons[1].contains("size-limit"), "{}", reasons[1]);
        assert_eq!(reasons[2], "Denied by rule: deny-restricted");
        assert_eq!(response.audit.tags, vec!["mqtt", "detect-only", "publish"]);
    }

    #[tokio::test]
    async fn detect_only_frame_still_stops_at_a_close() {
        let agent = connected(detect_only_agent()).await;
        let data = [acl_denied_publish(), disconnect_packet(), allowed_publish()].concat();

        let response = agent.on_websocket_frame(binary(&data)).await;

        assert_eq!(outcome(&response), Expect::Close(0x01));
        assert_eq!(rule_ids(&response), vec!["no-context"]);
    }

    #[tokio::test]
    async fn detect_only_frame_that_cannot_be_read_is_still_refused() {
        let agent = connected(detect_only_agent()).await;
        let data = [acl_denied_publish(), vec![0x00, 0x00]].concat();

        let whole = agent.on_websocket_frame(binary(&data)).await;
        let fragment = agent
            .on_websocket_frame(frame("binary", false, &data))
            .await;

        assert_eq!(outcome(&whole), Expect::Drop);
        assert_eq!(outcome(&fragment), Expect::Close(1002));
    }

    #[tokio::test]
    async fn detect_only_fragment_is_allowed() {
        let agent = connected(detect_only_agent()).await;

        let first = agent
            .on_websocket_frame(frame("binary", false, &acl_denied_publish()))
            .await;
        let last = agent
            .on_websocket_frame(frame("continuation", true, &acl_denied_publish()))
            .await;

        assert_eq!(outcome(&first), Expect::Allow);
        assert_eq!(outcome(&last), Expect::Allow);
        assert_eq!(rule_ids(&last), vec!["acl-denied"]);
    }

    // ---- messages split over several frames ----

    /// One frame of a sequence, and the decision it should get.
    struct Step {
        opcode: &'static str,
        fin: bool,
        from_client: bool,
        data: Vec<u8>,
        expect: Expect,
    }

    fn step(opcode: &'static str, fin: bool, data: Vec<u8>, expect: Expect) -> Step {
        Step {
            opcode,
            fin,
            from_client: true,
            data,
            expect,
        }
    }

    fn from_server(step: Step) -> Step {
        Step {
            from_client: false,
            ..step
        }
    }

    #[tokio::test]
    async fn only_frames_of_a_binary_message_are_inspected() {
        use Expect::{Allow, Close, Drop};
        let ok = allowed_publish;
        let denied = acl_denied_publish;
        let cases = [
            (
                "a refused continuation closes the connection",
                vec![
                    step("binary", false, ok(), Allow),
                    step("continuation", true, denied(), Close(1008)),
                ],
            ),
            (
                "a refused continuation in the middle closes the connection",
                vec![
                    step("binary", false, ok(), Allow),
                    step("continuation", false, denied(), Close(1008)),
                ],
            ),
            (
                "allowed frames of a three-frame message pass",
                vec![
                    step("binary", false, ok(), Allow),
                    step("continuation", false, ok(), Allow),
                    step("continuation", true, ok(), Allow),
                ],
            ),
            (
                "a refused first fragment closes the connection",
                vec![step("binary", false, denied(), Close(1008))],
            ),
            (
                "a refused whole message is dropped",
                vec![step("binary", true, denied(), Drop)],
            ),
            (
                "a continuation of a text message passes",
                vec![
                    step("text", false, b"hello".to_vec(), Allow),
                    step("continuation", true, denied(), Allow),
                ],
            ),
            (
                "a continuation with no message in progress passes",
                vec![step("continuation", true, denied(), Allow)],
            ),
            (
                "a continuation after the message ended passes",
                vec![
                    step("binary", true, ok(), Allow),
                    step("continuation", true, denied(), Allow),
                ],
            ),
            (
                "a text message after a binary message passes",
                vec![
                    step("binary", false, ok(), Allow),
                    step("continuation", true, ok(), Allow),
                    step("text", false, b"hello".to_vec(), Allow),
                    step("continuation", true, denied(), Allow),
                ],
            ),
            (
                "a text frame starts a new message",
                vec![
                    step("binary", false, ok(), Allow),
                    step("text", false, b"hello".to_vec(), Allow),
                    step("continuation", true, denied(), Allow),
                ],
            ),
            (
                "ping and pong do not end the message",
                vec![
                    step("binary", false, ok(), Allow),
                    step("ping", true, vec![], Allow),
                    step("pong", true, vec![], Allow),
                    step("continuation", true, denied(), Close(1008)),
                ],
            ),
            (
                "frames from the server do not end the message",
                vec![
                    step("binary", false, ok(), Allow),
                    from_server(step("binary", true, denied(), Allow)),
                    from_server(step("text", true, b"hello".to_vec(), Allow)),
                    step("continuation", true, denied(), Close(1008)),
                ],
            ),
            (
                "a continuation from the server is not inspected",
                vec![
                    step("binary", false, ok(), Allow),
                    from_server(step("continuation", true, denied(), Allow)),
                ],
            ),
            (
                "an empty final continuation passes",
                vec![
                    step("binary", false, ok(), Allow),
                    step("continuation", true, vec![], Allow),
                ],
            ),
        ];
        for (case, steps) in cases {
            let agent = connected(agent()).await;
            for (n, step) in steps.into_iter().enumerate() {
                let mut event = frame(step.opcode, step.fin, &step.data);
                event.client_to_server = step.from_client;

                let response = agent.on_websocket_frame(event).await;

                assert_eq!(outcome(&response), step.expect, "{case}, frame {n}");
            }
        }
    }

    #[tokio::test]
    async fn closing_a_fragmented_message_keeps_the_details_of_the_refusal() {
        let agent = connected(agent()).await;

        let response = agent
            .on_websocket_frame(frame("binary", false, &acl_denied_publish()))
            .await;

        assert_eq!(outcome(&response), Expect::Close(1008));
        assert_eq!(rule_ids(&response), vec!["acl-denied"]);
        assert_eq!(response.audit.reason_codes.len(), 1);
        assert_eq!(
            response.audit.tags,
            vec!["mqtt", "blocked", "connection-closed"]
        );
    }

    #[tokio::test]
    async fn disconnect_inside_a_fragment_does_not_end_the_message() {
        let agent = connected(agent()).await;

        let first = agent
            .on_websocket_frame(frame("binary", false, &disconnect_packet()))
            .await;
        let last = agent
            .on_websocket_frame(frame("continuation", true, &allowed_publish()))
            .await;

        assert_eq!(outcome(&first), Expect::Allow);
        // The rest of the message is still read; the connection is gone.
        assert_eq!(outcome(&last), Expect::Close(0x01));
        assert_eq!(rule_ids(&last), vec!["no-context"]);
    }

    // ---- state of a finished connection ----

    #[tokio::test]
    async fn request_complete_removes_the_connection() {
        let agent = connected(agent()).await;
        let before = agent.on_websocket_frame(binary(&allowed_publish())).await;
        assert_eq!(outcome(&before), Expect::Allow);

        agent.on_request_complete(request_complete()).await;
        let after = agent.on_websocket_frame(binary(&allowed_publish())).await;

        assert_eq!(outcome(&after), Expect::Close(0x01));
        assert_eq!(rule_ids(&after), vec!["no-context"]);
        assert!(agent.connections.is_empty());
    }

    #[tokio::test]
    async fn request_complete_ends_a_binary_message_in_progress() {
        let agent = connected(agent()).await;
        agent
            .on_websocket_frame(frame("binary", false, &allowed_publish()))
            .await;

        agent.on_request_complete(request_complete()).await;
        let stray = agent
            .on_websocket_frame(frame("continuation", true, &acl_denied_publish()))
            .await;

        assert_eq!(outcome(&stray), Expect::Allow);
    }

    #[tokio::test]
    async fn message_state_is_kept_only_while_a_message_is_open() {
        let agent = connected(agent()).await;
        let on = |id: &str, mut event: WebSocketFrameEvent| {
            event.correlation_id = id.to_string();
            event
        };

        // A message that ends with FIN leaves nothing behind.
        agent
            .on_websocket_frame(frame("binary", false, &allowed_publish()))
            .await;
        assert_eq!(agent.binary_messages.len(), 1);
        agent
            .on_websocket_frame(frame("continuation", true, &allowed_publish()))
            .await;
        assert!(agent.binary_messages.is_empty());

        // Neither does a whole message, a text message or a close.
        agent.on_websocket_frame(binary(&allowed_publish())).await;
        agent
            .on_websocket_frame(frame("text", true, b"hello"))
            .await;
        assert!(agent.binary_messages.is_empty());
        let refused = agent
            .on_websocket_frame(frame("binary", false, &acl_denied_publish()))
            .await;
        assert_eq!(outcome(&refused), Expect::Close(1008));
        assert!(agent.binary_messages.is_empty());

        // The ones left open are removed when their connections complete.
        for n in 0..10 {
            let id = format!("open-{n}");
            agent
                .on_websocket_frame(on(&id, binary(&connect_packet())))
                .await;
            agent
                .on_websocket_frame(on(&id, frame("binary", false, &allowed_publish())))
                .await;
        }
        assert_eq!(agent.binary_messages.len(), 10);
        assert_eq!(agent.connections.len(), 11);
        for n in 0..10 {
            let mut event = request_complete();
            event.correlation_id = format!("open-{n}");
            agent.on_request_complete(event).await;
        }
        assert!(agent.binary_messages.is_empty());
        assert_eq!(agent.connections.len(), 1);
        agent.on_request_complete(request_complete()).await;
        assert!(agent.connections.is_empty());
    }

    // ---- frames that carry one packet behave as before ----

    #[tokio::test]
    async fn single_packet_frames_keep_their_decisions_and_metadata() {
        let agent = agent();

        let connect = agent.on_websocket_frame(binary(&connect_packet())).await;
        assert_eq!(outcome(&connect), Expect::Allow);
        assert_eq!(connect.audit.tags, vec!["mqtt", "connect", "success"]);

        let allowed = agent.on_websocket_frame(binary(&allowed_publish())).await;
        assert_eq!(outcome(&allowed), Expect::Allow);
        assert_eq!(allowed.audit.tags, vec!["mqtt", "publish"]);

        let denied = agent
            .on_websocket_frame(binary(&acl_denied_publish()))
            .await;
        assert_eq!(outcome(&denied), Expect::Drop);
        assert_eq!(denied.audit.tags, vec!["mqtt", "blocked"]);
        assert_eq!(rule_ids(&denied), vec!["acl-denied"]);
        assert_eq!(denied.audit.reason_codes.len(), 1);

        let unreadable = agent.on_websocket_frame(binary(&[0x00, 0x00])).await;
        assert_eq!(outcome(&unreadable), Expect::Drop);
        assert_eq!(unreadable.audit.tags, vec!["mqtt", "error"]);
        assert_eq!(rule_ids(&unreadable), vec!["mqtt-parse-error"]);
        assert_eq!(
            unreadable.audit.reason_codes,
            vec!["Invalid MQTT packet".to_string()]
        );

        let truncated = agent.on_websocket_frame(binary(&[0x30, 0x05, 0x00])).await;
        assert_eq!(outcome(&truncated), Expect::Drop);

        let disconnect = agent.on_websocket_frame(binary(&disconnect_packet())).await;
        assert_eq!(outcome(&disconnect), Expect::Allow);
        assert!(agent.connections.is_empty());
    }
}
