declare module 'adm-zip' {
  class AdmZip {
    constructor(path?: string | Buffer);
    addFile(entryName: string, data: Buffer): void;
    addLocalFolder(path: string, zipPath?: string): void;
    extractAllTo(targetPath: string, overwrite?: boolean): void;
    getEntries(): { entryName: string; getData(): Buffer }[];
    readAsText(entry: { entryName: string; getData(): Buffer }, encoding?: string): string;
  }
  export default AdmZip;
}
