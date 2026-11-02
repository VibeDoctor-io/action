import { XMLParser } from 'fast-xml-parser';

export type ReportFormat = 'lcov' | 'cobertura';

export interface ReportFiles {
  format: ReportFormat;
  sources: string[];
  files: string[];
}

const LIST_TAGS = new Set(['source', 'package', 'class']);

const xmlParser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '',
  processEntities: false,
  parseTagValue: false,
  isArray: (tagName, _path, _leaf, isAttribute) => !isAttribute && LIST_TAGS.has(tagName),
});

export function readReportFiles(text: string): ReportFiles {
  const body = text.replace(/^﻿/, '').trimStart();
  return body.startsWith('<') ? readCobertura(body) : readLcov(body);
}

function readLcov(text: string): ReportFiles {
  const files: string[] = [];
  for (const line of text.split(/\r?\n/)) {
    if (line.startsWith('SF:')) files.push(line.slice(3));
  }
  if (files.length === 0) throw new Error('not an LCOV or Cobertura XML report');
  return { format: 'lcov', sources: [], files: unique(files) };
}

function readCobertura(text: string): ReportFiles {
  const coverage = xmlParser.parse(text)?.coverage;
  if (!coverage || typeof coverage !== 'object') throw new Error('not an LCOV or Cobertura XML report');
  if ('project' in coverage) throw new Error('Clover XML is not supported, send LCOV or Cobertura XML');

  const sources = asArray(coverage.sources?.source).filter(isText);
  const files = asArray(coverage.packages?.package)
    .flatMap((pkg) => asArray(pkg?.classes?.class))
    .map((cls) => cls?.filename)
    .filter(isText);
  return { format: 'cobertura', sources, files: unique(files) };
}

function asArray(value: unknown): any[] {
  return Array.isArray(value) ? value : [];
}

function isText(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0;
}

function unique(values: string[]): string[] {
  return [...new Set(values)];
}
