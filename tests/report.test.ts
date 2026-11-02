import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { readReportFiles } from '../src/report.js';

const fixture = (name: string) => fs.readFileSync(path.join(import.meta.dirname, 'fixtures', name), 'utf8');

describe('readReportFiles on real reports', () => {
  it('reads Vitest LCOV', () => {
    expect(readReportFiles(fixture('vitest-lcov.info'))).toEqual({
      format: 'lcov',
      sources: [],
      files: ['src\\math.js', 'src\\untested.js'],
    });
  });

  it('reads Jest LCOV', () => {
    expect(readReportFiles(fixture('jest-lcov.info')).files).toEqual(['src\\math.js']);
  });

  it('reads coverage.py LCOV with CRLF line endings', () => {
    expect(readReportFiles(fixture('coveragepy.lcov')).files).toEqual(['pkg\\__init__.py', 'pkg\\calc.py', 'test_calc.py']);
  });

  it('reads Vitest Cobertura with its DOCTYPE', () => {
    expect(readReportFiles(fixture('vitest-cobertura.xml'))).toEqual({
      format: 'cobertura',
      sources: ['C:/build/covtest/js'],
      files: ['src\\math.js', 'src\\untested.js'],
    });
  });

  it('reads coverage.py Cobertura with CRLF, tabs and comments', () => {
    expect(readReportFiles(fixture('coveragepy.xml'))).toEqual({
      format: 'cobertura',
      sources: ['C:\\build\\covtest\\py'],
      files: ['test_calc.py', 'pkg/__init__.py', 'pkg/calc.py'],
    });
  });

  it('refuses Clover XML by name', () => {
    expect(() => readReportFiles(fixture('jest-clover.xml'))).toThrow(/Clover XML is not supported/);
  });
});

describe('readReportFiles edge cases', () => {
  it('accepts a byte order mark before LCOV', () => {
    expect(readReportFiles('\uFEFFSF:a.js\nDA:1,1\nend_of_record\n').files).toEqual(['a.js']);
  });

  it('lists a file once when LCOV repeats it', () => {
    expect(readReportFiles('SF:a.js\nend_of_record\nSF:a.js\nend_of_record\n').files).toEqual(['a.js']);
  });

  it('reads a Cobertura report with one package and one class', () => {
    const xml = '<coverage><sources><source>/w</source></sources><packages><package><classes><class filename="a.py"/></classes></package></packages></coverage>';
    expect(readReportFiles(xml)).toEqual({ format: 'cobertura', sources: ['/w'], files: ['a.py'] });
  });

  it('keeps entity text as written and never expands DOCTYPE entities', () => {
    const xml =
      '<!DOCTYPE coverage [<!ENTITY big "xxxxxxxxxx">]><coverage><packages><package><classes>' +
      '<class filename="&big;.js"/><class filename="a&amp;b.js"/></classes></package></packages></coverage>';
    expect(readReportFiles(xml).files).toEqual(['&big;.js', 'a&amp;b.js']);
  });

  it('keeps a numeric source path as text', () => {
    const xml = '<coverage><sources><source>2024</source></sources><packages/></coverage>';
    expect(readReportFiles(xml).sources).toEqual(['2024']);
  });

  it.each([
    ['plain text', 'hello world'],
    ['an empty file', ''],
    ['an HTML page', '<html><body>coverage</body></html>'],
    ['other XML', '<?xml version="1.0"?><testsuites/>'],
  ])('refuses %s', (_label, text) => {
    expect(() => readReportFiles(text)).toThrow(/not an LCOV or Cobertura XML report/);
  });
});
