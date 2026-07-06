import { readFileSync } from "fs";
import { detect, summarize } from "../lib/detect.ts";

const scan = JSON.parse(readFileSync(new URL("./real_scan_output.json", import.meta.url), "utf8"));
const findings = detect(scan);
console.log(JSON.stringify(findings.map(f => ({ table: f.table, severity: f.severity, title: f.title })), null, 2));
console.log(summarize(findings));
