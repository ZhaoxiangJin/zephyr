import { isDirectRun } from "./svg_common.mjs";
import { generateArchitectureOverviewSvg } from "./generate_architecture_overview_svg.mjs";
import { generateLoaderPipelineSvg } from "./generate_loader_pipeline_svg.mjs";
import { generateProgramLifecycleSvg } from "./generate_program_lifecycle_svg.mjs";
import { generateDispatchSnapshotSvg } from "./generate_dispatch_snapshot_svg.mjs";
import { generateVerifierRuntimeSvg } from "./generate_verifier_runtime_svg.mjs";
import { generateBackendBridgeSvg } from "./generate_backend_bridge_svg.mjs";
import { generateThreadSwitchCounterFlowSvg } from "./generate_thread_switch_counter_flow_svg.mjs";
import { generatePmResidencyFlowSvg } from "./generate_pm_residency_flow_svg.mjs";

export async function generateEbpfStoryboardSvgs() {
  const outputs = [];

  outputs.push(await generateArchitectureOverviewSvg());
  outputs.push(await generateLoaderPipelineSvg());
  outputs.push(await generateProgramLifecycleSvg());
  outputs.push(await generateDispatchSnapshotSvg());
  outputs.push(await generateVerifierRuntimeSvg());
  outputs.push(await generateBackendBridgeSvg());
    outputs.push(await generateThreadSwitchCounterFlowSvg());
    outputs.push(await generatePmResidencyFlowSvg());

  return outputs;
}

if (isDirectRun(import.meta.url)) {
  const outputs = await generateEbpfStoryboardSvgs();

  for (const output of outputs) {
    console.log(`wrote ${output}`);
  }
}