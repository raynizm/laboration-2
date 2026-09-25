/**
 * @file Test Runner Script
 * @description Runs comprehensive tests on password module and generates TEST_REPORT.md
 */

import PasswordGenerator from '../../src/PasswordGenerator.js';
import StrengthAnalyzer from '../../src/StrengthAnalyzer.js';
import SecureHasher from '../../src/SecureHasher.js';
import { writeFileSync } from 'fs';

const results = [];

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

// ─── Orchestrator & Report Generation ────────────────────────────────

async function runAllTests() {
  await Promise.all([
    testBasicRandomGeneration(),
    testStrongPasswordContainsAllTypes(),
    testLengthValidationRejectsLessThan8(),
    testCharacterSetFiltering(),
    testPatternModeGeneratesRepeatingSeed(),
    testSeparatorWorksInPatternMode(),
    testPatternLengthTruncation(),
    testStrengthAnalyzerCalculatesEntropy(),
    testStrengthLevelsClassification(),
    testConsistentHashingWithSameSalt(),
    testDifferentSaltsProduceDifferentHashes(),
    testPasswordVerificationSuccessful(),
    testWrongPasswordVerificationFails()
  ]);

  const report = generateTestReport(results);
  writeFileSync('./TEST_REPORT.md', report, 'utf8');
  console.log('\n✅ All tests completed! Report saved to TEST_REPORT.md');
}

function generateTestReport(results) {
  let report = `# Test Report - Password Module\n`;
  report += `\n## Overview\n`;
  report += `- Total tests run: ${results.length}\n`;
  report += `- Passed: ${results.filter(r => r.passed).length}\n`;
  report += `- Failed: ${results.filter(r => !r.passed).length}\n`;
  report += `\n## Test Results\n\n| # | Test Case | How It Was Tested | Result |\n|---|-----------|-------------------|--------|\n`;

  results.forEach((result, index) => {
    const status = result.passed ? '✅ Passed' : '❌ Failed';
    report += `| ${index + 1} | ${result.test} | ${status} | ${result.details} |\n`;
  });

  return report;
}

// ─── Individual Test Functions ──────────────────────────────────────

async function testBasicRandomGeneration() {
  try {
    const pwd = new PasswordGenerator().generate(20);
    assert(pwd.length === 20, `Expected length 20, got ${pwd.length}`);
    results.push({ passed: true, test: 'Standard random generation produces correct length', details: `Length: ${pwd.length}` });
  } catch (e) { results.push({ passed: false, test: e.test || 'Basic Random Generation', details: e.message }); }
}

async function testStrongPasswordContainsAllTypes() {
  try {
    const generator = new PasswordGenerator();
    const strongPwd = generator.generateStrong();
    assert(/[a-z]/.test(strongPwd), "Missing lowercase");
    assert(/[A-Z]/.test(strongPwd), "Missing uppercase");
    assert(/\d/.test(strongPwd), "Missing numbers");
    results.push({ passed: true, test: 'Strong password contains all required character types', details: strongPwd });
  } catch (e) { results.push({ passed: false, test: e.test || 'Strong Generation', details: e.message }); }
}

async function testLengthValidationRejectsLessThan8() {
  try {
    new PasswordGenerator().generate(5);
    throw new Error('Should have thrown');
  } catch (e) {
    if (e.message.includes('at least 8')) results.push({ passed: true, test: 'Length validation rejects <8', details: e.message });
    else results.push({ passed: false, test: 'Validation', details: e.message });
  }
}

async function testCharacterSetFiltering() {
  try {
    const pwd = new PasswordGenerator().generate(12, { lowercase: true, numbers: true });
    assert(!/[A-Z]/.test(pwd), "Uppercase found");
    assert(!/[^a-z0-9]/.test(pwd), "Symbols found");
    results.push({ passed: true, test: 'Character set filtering works correctly', details: pwd });
  } catch (e) { results.push({ passed: false, test: e.test || 'Filtering', details: e.message }); }
}

async function testPatternModeGeneratesRepeatingSeed() {
  try {
    const generator = new PasswordGenerator();
    const patternPwd = generator.generate(12, { pattern: true, seedLength: 6 });
    const seed = patternPwd.substring(0, 6);
    assert(patternPwd.startsWith(seed + '-'), "Seed not repeating correctly");
    results.push({ passed: true, test: 'Pattern mode generates repeating seed string', details: patternPwd });
  } catch (e) { results.push({ passed: false, test: e.test || 'Pattern Mode', details: e.message }); }
}

async function testSeparatorWorksInPatternMode() {
  try {
    const pwd = new PasswordGenerator().generate(14, { pattern: true, seedLength: 6, separator: '-' });
    assert(pwd.includes('-'), "Separator missing");
    results.push({ passed: true, test: 'Separator works correctly in pattern mode', details: pwd.substring(0, 15) });
  } catch (e) { results.push({ passed: false, test: e.test || 'Pattern Separator', details: e.message }); }
}

async function testPatternLengthTruncation() {
  try {
    const pwd = new PasswordGenerator().generate(14, { pattern: true, seedLength: 6 });
    assert(pwd.length === 14, `Expected length 14, got ${pwd.length}`);
    results.push({ passed: true, test: 'Pattern length truncation is accurate', details: pwd });
  } catch (e) { results.push({ passed: false, test: e.test || 'Pattern Truncation', details: e.message }); }
}

async function testStrengthAnalyzerCalculatesEntropy() {
  try {
    const pwd = new PasswordGenerator().generate(20);
    const analysis = new StrengthAnalyzer().analyze(pwd);
    assert(analysis.entropy > 100, "Entropy too low");
    results.push({ passed: true, test: 'StrengthAnalyzer calculates entropy correctly', details: `Entropy: ${analysis.entropy}` });
  } catch (e) { results.push({ passed: false, test: e.test || 'Entropy Calculation', details: e.message }); }
}

async function testStrengthLevelsClassification() {
  try {
    const analyzer = new StrengthAnalyzer();
    const weak = analyzer.analyze('abc');
    assert(weak.strength === 'weak', "Weak password not flagged");
    
    const strong = analyzer.analyze(new PasswordGenerator().generateStrong());
    assert(strong.strength === 'strong', "Strong password not flagged");
    
    results.push({ passed: true, test: 'Strength levels classified correctly (weak/strong)', details: `Weak: ${weak.strength}, Strong: ${strong.strength}` });
  } catch (e) { results.push({ passed: false, test: e.test || 'Classification', details: e.message }); }
}

async function testConsistentHashingWithSameSalt() {
  try {
    const hasher = new SecureHasher();
    const plain = "test123!";
    const hashResult1 = await hasher.hashWithSalt(plain, 'fixed_salt');
    const hashResult2 = await hasher.hashWithSalt(plain, 'fixed_salt');
    assert(hashResult1.hash === hashResult2.hash, "Hashes not consistent");
    results.push({ passed: true, test: 'Consistent hashing with same salt', details: `Hash matches` });
  } catch (e) { results.push({ passed: false, test: e.test || 'Consistent Hashing', details: e.message }); }
}

async function testDifferentSaltsProduceDifferentHashes() {
  try {
    const hasher = new SecureHasher();
    const plain = "test123!";
    const hashResult1 = await hasher.hashWithSalt(plain, 'salt_a');
    const hashResult2 = await hasher.hashWithSalt(plain, 'salt_b');
    assert(hashResult1.hash !== hashResult2.hash, "Hashes not unique");
    results.push({ passed: true, test: 'Different salts produce different hashes', details: `Differs` });
  } catch (e) { results.push({ passed: false, test: e.test || 'Salt Variation', details: e.message }); }
}

async function testPasswordVerificationSuccessful() {
  try {
    const hasher = new SecureHasher();
    const plain = "securepassword123!";
    const hashResult = await hasher.hashWithSalt(plain);
    assert(hasher.verifyPassword(plain, hashResult.hash, hashResult.salt), "Verification failed");
    results.push({ passed: true, test: 'Password verification successful', details: `Verified` });
  } catch (e) { results.push({ passed: false, test: e.test || 'Verification', details: e.message }); }
}

async function testWrongPasswordVerificationFails() {
  try {
    const hasher = new SecureHasher();
    const hashResult = await hasher.hashWithSalt("securepassword123!");
    assert(!hasher.verifyPassword("wrong_password", hashResult.hash, hashResult.salt), "Wrong password accepted");
    results.push({ passed: true, test: 'Wrong password verification fails correctly', details: `Rejected` });
  } catch (e) { results.push({ passed: false, test: e.test || 'Rejection', details: e.message }); }
}

runAllTests().catch(console.error);
