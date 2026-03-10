import { ScanReport } from '../types.js';

export const renderJson = (report: ScanReport): string => {
  return JSON.stringify(report, null, 2);
};
