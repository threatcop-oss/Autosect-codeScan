import fs from 'fs-extra';
import { ScanReport, OutputFormat } from '../types.js';
import { renderJson } from './json.js';
import { renderSarif } from './sarif.js';
import { renderMarkdown } from './markdown.js';
import { renderConsole } from './console.js';
import { renderHtml } from './html.js';

export const formatReport = async (
  report: ScanReport,
  format: OutputFormat
): Promise<string> => {
  switch (format) {
    case 'sarif':
      return renderSarif(report);
    case 'html':
      return renderHtml(report);
    case 'markdown':
      return renderMarkdown(report);
    case 'console':
      return renderConsole(report);
    case 'json':
    default:
      return renderJson(report);
  }
};

export const writeReport = async (
  report: ScanReport,
  format: OutputFormat,
  outputPath?: string
): Promise<string> => {
  const rendered = await formatReport(report, format);
  if (outputPath) {
    await fs.outputFile(outputPath, rendered, 'utf8');
  }
  return rendered;
};
