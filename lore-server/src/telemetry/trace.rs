// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::RwLock;
use std::time::Duration;

use lore_error_set::prelude::*;
use lore_telemetry::ExporterConfig;
use lore_telemetry::TelemetryError;
use lore_telemetry::TraceConfig;
use lore_telemetry::tracing::fields::SAMPLING_TIER_LOW;
use opentelemetry::Context;
use opentelemetry::KeyValue;
use opentelemetry::trace::Link;
use opentelemetry::trace::SpanKind;
use opentelemetry::trace::TraceId;
use opentelemetry_otlp::SpanExporter;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::trace::BatchConfigBuilder;
use opentelemetry_sdk::trace::BatchSpanProcessor;
use opentelemetry_sdk::trace::RandomIdGenerator;
use opentelemetry_sdk::trace::Sampler;
use opentelemetry_sdk::trace::SamplingResult;
use opentelemetry_sdk::trace::SdkTracerProvider;
use opentelemetry_sdk::trace::ShouldSample;
use tokio::runtime::Handle;
use tracing::debug;
use tracing::error;

use super::resource::resource;
use super::resource_provider::ResourceDetectorProvider;

static TRACER_PROVIDER: OnceLock<RwLock<Arc<SdkTracerProvider>>> = OnceLock::new();

fn tracer_provider_lock() -> &'static RwLock<Arc<SdkTracerProvider>> {
    TRACER_PROVIDER.get_or_init(|| RwLock::new(Arc::new(SdkTracerProvider::builder().build())))
}

/// Sets the global tracer provider.
pub fn set_tracer_provider(provider: SdkTracerProvider) {
    if let Ok(ref mut tracer_provider) = tracer_provider_lock().write() {
        **tracer_provider = Arc::new(provider);
        debug!("Set new tracer provider");
    } else {
        error!("Failed to obtain write lock to set tracer provider");
    }
}

/// Gets a reference to the global tracer provider.
#[allow(dead_code)]
pub fn tracer_provider() -> Arc<SdkTracerProvider> {
    if let Ok(provider) = tracer_provider_lock().read() {
        provider.clone()
    } else {
        error!("Failed to obtain read lock for tracer provider, returning a no-op provider");
        Arc::new(SdkTracerProvider::builder().build())
    }
}

#[derive(Clone, Debug)]
struct PerOpSampler {
    low_tier: Sampler,
    default_: Sampler,
}

impl PerOpSampler {
    fn new(default_rate: f64, low_tier_rate: f64) -> Self {
        Self {
            low_tier: Sampler::TraceIdRatioBased(low_tier_rate),
            default_: Sampler::TraceIdRatioBased(default_rate),
        }
    }
}

impl ShouldSample for PerOpSampler {
    fn should_sample(
        &self,
        parent_context: Option<&Context>,
        trace_id: TraceId,
        name: &str,
        span_kind: &SpanKind,
        attributes: &[KeyValue],
        links: &[Link],
    ) -> SamplingResult {
        let is_low_tier = attributes.iter().any(|kv| {
            kv.key.as_str() == SAMPLING_TIER_LOW
                && matches!(kv.value, opentelemetry::Value::Bool(true))
        });
        let inner = if is_low_tier {
            &self.low_tier
        } else {
            &self.default_
        };
        inner.should_sample(parent_context, trace_id, name, span_kind, attributes, links)
    }
}

/// Initializes an OTLP tracer provider for exporting traces.
pub fn init_tracer_provider(
    exporter_config: &ExporterConfig,
    trace_config: &TraceConfig,
    additional_labels: &Option<HashMap<String, String>>,
    runtime_handle: Handle,
    resource_detector_provider: Option<&dyn ResourceDetectorProvider>,
) -> Result<SdkTracerProvider, TelemetryError> {
    let sampler = Sampler::ParentBased(Box::new(PerOpSampler::new(
        trace_config.sample_rate,
        trace_config.sample_rate_low_tier,
    )));

    let exporter = SpanExporter::builder()
        .with_tonic()
        .with_endpoint(exporter_config.endpoint.clone())
        .with_timeout(Duration::from_millis(exporter_config.timeout))
        .build()
        .internal("Failed to build OTLP span exporter")?;

    let batch_config = BatchConfigBuilder::default()
        .with_max_queue_size(exporter_config.queue_size)
        .build();

    let processor = BatchSpanProcessor::builder(exporter)
        .with_batch_config(batch_config)
        .build();

    let tracer_provider = SdkTracerProvider::builder()
        .with_span_processor(processor)
        .with_sampler(sampler)
        .with_id_generator(RandomIdGenerator::default())
        .with_resource(resource(
            additional_labels,
            runtime_handle,
            resource_detector_provider,
        ))
        .build();

    set_tracer_provider(tracer_provider.clone());

    Ok(tracer_provider)
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::time::SystemTime;

    use opentelemetry::trace::Span;
    use opentelemetry::trace::SpanContext;
    use opentelemetry::trace::SpanId;
    use opentelemetry::trace::Status;
    use opentelemetry::trace::TraceContextExt;
    use opentelemetry::trace::TraceFlags;
    use opentelemetry::trace::TraceState;
    use opentelemetry_sdk::trace::SamplingDecision;

    use super::*;

    #[derive(Debug)]
    struct TestSpan(SpanContext);

    impl Span for TestSpan {
        fn add_event_with_timestamp<T>(
            &mut self,
            _name: T,
            _timestamp: SystemTime,
            _attributes: Vec<KeyValue>,
        ) where
            T: Into<Cow<'static, str>>,
        {
        }
        fn span_context(&self) -> &SpanContext {
            &self.0
        }
        fn is_recording(&self) -> bool {
            false
        }
        fn set_attribute(&mut self, _attribute: KeyValue) {}
        fn set_status(&mut self, _status: Status) {}
        fn update_name<T>(&mut self, _new_name: T)
        where
            T: Into<Cow<'static, str>>,
        {
        }
        fn add_link(&mut self, _span_context: SpanContext, _attributes: Vec<KeyValue>) {}
        fn end_with_timestamp(&mut self, _timestamp: SystemTime) {}
    }

    fn low_tier_attrs() -> Vec<KeyValue> {
        vec![KeyValue::new(SAMPLING_TIER_LOW, true)]
    }

    fn splitmix64(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn deterministic_trace_id(state: &mut u64) -> TraceId {
        let high = splitmix64(state) as u128;
        let low = splitmix64(state) as u128;
        TraceId::from_bytes(((high << 64) | low).to_be_bytes())
    }

    fn ratio_for(sampler: &impl ShouldSample, attributes: &[KeyValue], n: usize, seed: u64) -> f64 {
        let mut state = seed;
        let mut sampled = 0usize;
        for _ in 0..n {
            let trace_id = deterministic_trace_id(&mut state);
            let result = sampler.should_sample(
                None,
                trace_id,
                "AnySpanName",
                &SpanKind::Internal,
                attributes,
                &[],
            );
            if result.decision == SamplingDecision::RecordAndSample {
                sampled += 1;
            }
        }
        sampled as f64 / n as f64
    }

    fn fixed_trace_id() -> TraceId {
        TraceId::from_bytes(0x1111_2222_3333_4444_5555_6666_7777_8888u128.to_be_bytes())
    }

    fn decision_for(sampler: &impl ShouldSample, attributes: &[KeyValue]) -> SamplingDecision {
        sampler
            .should_sample(
                None,
                fixed_trace_id(),
                "AnySpanName",
                &SpanKind::Internal,
                attributes,
                &[],
            )
            .decision
    }

    #[test]
    fn low_tier_rate_observed_when_attribute_present() {
        let sampler = PerOpSampler::new(0.0, 0.25);
        let n = 10_000;
        let observed = ratio_for(&sampler, &low_tier_attrs(), n, 0xC0FFEE_u64);
        let expected = 0.25;
        let z = 4.75342_f64;
        let tolerance = z * (expected * (1.0 - expected) / n as f64).sqrt();
        assert!(
            (observed - expected).abs() <= tolerance,
            "low-tier ratio {observed} outside tolerance {tolerance} of {expected}"
        );
    }

    #[test]
    fn default_rate_observed_when_attribute_absent() {
        let sampler = PerOpSampler::new(0.5, 0.0);
        let n = 10_000;
        let observed = ratio_for(&sampler, &[], n, 0xDEADBEEF_u64);
        let expected = 0.5;
        let z = 4.75342_f64;
        let tolerance = z * (expected * (1.0 - expected) / n as f64).sqrt();
        assert!(
            (observed - expected).abs() <= tolerance,
            "default-rate ratio {observed} outside tolerance {tolerance} of {expected}"
        );
    }

    fn sampled_parent_context() -> Context {
        let span_context = SpanContext::new(
            TraceId::from(1),
            SpanId::from(1),
            TraceFlags::SAMPLED,
            true,
            TraceState::default(),
        );
        Context::current_with_span(TestSpan(span_context))
    }

    #[test]
    fn sampled_parent_forces_record_and_sample() {
        let sampler = Sampler::ParentBased(Box::new(PerOpSampler::new(0.0, 0.0)));
        let parent = sampled_parent_context();

        for attrs in [Vec::new(), low_tier_attrs()] {
            let result = sampler.should_sample(
                Some(&parent),
                fixed_trace_id(),
                "AnySpanName",
                &SpanKind::Internal,
                &attrs,
                &[],
            );
            assert_eq!(
                result.decision,
                SamplingDecision::RecordAndSample,
                "sampled parent did not force RecordAndSample for attrs {attrs:?}"
            );
        }
    }

    #[test]
    fn low_tier_attribute_routes_to_low_tier_sampler() {
        let low_only = PerOpSampler::new(0.0, 1.0);
        assert_eq!(
            decision_for(&low_only, &low_tier_attrs()),
            SamplingDecision::RecordAndSample,
            "low-tier attribute was dropped under low_tier_rate=1.0, default_rate=0.0"
        );

        let default_only = PerOpSampler::new(1.0, 0.0);
        assert_eq!(
            decision_for(&default_only, &low_tier_attrs()),
            SamplingDecision::Drop,
            "low-tier attribute was sampled under low_tier_rate=0.0, default_rate=1.0"
        );
    }

    #[test]
    fn absent_attribute_routes_to_default_sampler() {
        let default_only = PerOpSampler::new(1.0, 0.0);
        assert_eq!(
            decision_for(&default_only, &[]),
            SamplingDecision::RecordAndSample,
            "absent attribute was dropped under default_rate=1.0, low_tier_rate=0.0"
        );

        let low_only = PerOpSampler::new(0.0, 1.0);
        assert_eq!(
            decision_for(&low_only, &[]),
            SamplingDecision::Drop,
            "absent attribute was sampled under default_rate=0.0, low_tier_rate=1.0"
        );
    }

    #[test]
    fn false_attribute_routes_to_default_sampler() {
        let default_only = PerOpSampler::new(1.0, 0.0);
        let attrs = vec![KeyValue::new(SAMPLING_TIER_LOW, false)];
        assert_eq!(
            decision_for(&default_only, &attrs),
            SamplingDecision::RecordAndSample,
            "Bool(false) attribute should route to default sampler"
        );
    }

    #[test]
    fn unrelated_attributes_do_not_affect_routing() {
        let default_only = PerOpSampler::new(1.0, 0.0);
        let attrs = vec![
            KeyValue::new("rpc.system", "grpc"),
            KeyValue::new("transport", "quic"),
        ];
        assert_eq!(
            decision_for(&default_only, &attrs),
            SamplingDecision::RecordAndSample,
            "unrelated attributes should route to default sampler"
        );
    }
}
