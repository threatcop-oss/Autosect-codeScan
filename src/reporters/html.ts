import fs from 'fs-extra';
import Handlebars from 'handlebars';
import { ScanReport } from '../types.js';

const templatePath = new URL('../templates/report.hbs', import.meta.url);

export const renderHtml = async (report: ScanReport): Promise<string> => {
  const templateSource = await fs.readFile(templatePath, 'utf8');
  const template = Handlebars.compile(templateSource);

  return template({
    report,
    summary: report.summary,
    findings: report.findings
  });
};
