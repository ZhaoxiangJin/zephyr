import { generateEbpfStoryboardSvgs } from "./generate_ebpf_storyboard_svgs.mjs";
import { isDirectRun } from "./svg_common.mjs";

export async function generateSvgs() {
  return generateEbpfStoryboardSvgs();
}

if (isDirectRun(import.meta.url)) {
  const outputs = await generateSvgs();

  for (const output of outputs) {
    console.log(`wrote ${output}`);
  }
}