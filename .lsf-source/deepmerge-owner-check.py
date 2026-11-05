"""Bounded Linux check of the reviewed source, tamper refusals and action bundles."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

BASE = '9244ec9f4725400c84054e3e6ec97514cadddf53'
SOURCE = '60bd0613e09bef8a77464828b6d476147aeb3385'
TREE = '578e888fbea3faf619b37e947f749242001b2aa0'
BRANCH = 'diag/deepmerge-source-owner-20261105'
ROOT = Path(__file__).resolve().parents[1]
SCRIPT = '.lsf-source/deepmerge-owner-check.py'
WORKFLOW = '.github/workflows/lsf-deepmerge-source-owner.yml'
ARCHIVE = '.lsf-source/deepmerge-4.3.1-lsf-prototype-v1.tar'
REPAIR = '.lsf-source/deepmerge-4.3.1-lsf-prototype-v1.repair.json'
VERIFIER = '.lsf-source/verify-installed-deepmerge.mjs'
STATE = (Path(os.environ['RUNNER_TEMP']) / 'lsf-deepmerge-owner').resolve()
assert STATE != ROOT and ROOT not in STATE.parents
FILES = {
    '.github/workflows/pr-check-dist.yml': 'd84c57ee8d8a16ccb90e634ab178971582d4cceccbcf7891f3df74c5879267d0',
    'package-lock.json': 'a4d4e4834d16cc2655b73066144923018ec59f38497b7d37d549fa22ecd1d424',
    'package.json': '830926dc4fc6b8357b85ee84855aa6c8dbd42569884bbadf932fb54401a22e7e',
    ARCHIVE: 'c4ca0f4eb3a2464c026bc3dec5d9eaf04544aed24c3fd1d77da95f85e36c369f',
    REPAIR: 'e402617d1e791c4bed35768b6c34ba68c370c076551495e738de0731ad2049c7',
    VERIFIER: '55367db845fb579dd45a1a16924bf017c0ddc8f84162d833e368c24a7d629cf7',
}
BUNDLES = {
    'dist/wasmtime/setup/index.js': 'cd4680b4dcb503403a8c7948967f34a7a94b8e8e38637d200a6ae0a998bfc7d6',
    'dist/wasm-tools/setup/index.js': 'dc2c9c7f21e3a7e4158257e6b00cc18cf66758f97aee2b323f2cd5b4c52f284b',
    'dist/wit-bindgen/setup/index.js': '3728dde40d2b6eecbce245e27de6386e467d90872b1d801b3767969a7c9fe521',
}
CASES = (ARCHIVE, REPAIR, 'node_modules/deepmerge/index.js',
         'node_modules/deepmerge/dist/cjs.js', 'node_modules/deepmerge/dist/umd.js',
         'package.json', 'package-lock.json')


def run(*args):
    return subprocess.check_output(args, cwd=ROOT, timeout=30).decode().strip()


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_check():
    assert sys.platform == 'linux'
    assert os.environ['GITHUB_REPOSITORY'] == 'KirilsTurkins/lsf-bytecodealliance-actions'
    assert os.environ['GITHUB_REF_NAME'] == BRANCH
    assert run('node', '--version') == 'v24.19.0'
    assert run('git', 'rev-parse', 'HEAD') == os.environ['GITHUB_SHA']
    assert run('git', 'rev-parse', 'HEAD^') == SOURCE
    assert run('git', 'rev-parse', SOURCE + '^{tree}') == TREE
    assert run('git', 'rev-parse', SOURCE + '^') == BASE
    rows = set(run('git', 'diff', '--name-status', SOURCE, 'HEAD').splitlines())
    assert rows == {'A\t' + SCRIPT, 'A\t' + WORKFLOW}
    assert sha(ROOT / SCRIPT) == os.environ['LSF_OWNER_SHA256']
    assert not subprocess.run(['git', 'diff', '--quiet'], cwd=ROOT).returncode
    assert not subprocess.run(['git', 'diff', '--cached', '--quiet'], cwd=ROOT).returncode
    for path, expected in (FILES | BUNDLES).items():
        item = ROOT / path
        assert item.is_file() and not item.is_symlink() and sha(item) == expected, path
    old = json.loads(subprocess.check_output(['git', 'show', BASE + ':package-lock.json'], cwd=ROOT))
    new = json.loads((ROOT/'package-lock.json').read_bytes())
    assert set(old['packages']) == set(new['packages'])
    assert [p for p in old['packages'] if old['packages'][p] != new['packages'][p]] == [
        '', 'node_modules/deepmerge']
    assert old['packages']['']['dependencies'] == new['packages']['']['dependencies']
    assert len(new['packages']) == 619
    return {'sourceCommit':SOURCE, 'sourceTree':TREE,
            'diagnosticCommit':os.environ['GITHUB_SHA'], 'bundleSha256':BUNDLES,
            'lockRecords':len(new['packages']), 'runtimeDependencyRecordsUnchanged':True}


def verify():
    return subprocess.run(['node', VERIFIER], cwd=ROOT, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=30, check=False)


def tamper_check():
    assert verify().returncode == 0
    refused = []
    for name in CASES:
        path = ROOT/name
        original = path.read_bytes()
        try:
            if name == 'package.json':
                data = json.loads(original)
                data['devDependencies']['deepmerge'] = '4.3.1'
                changed = json.dumps(data).encode()
            elif name == 'package-lock.json':
                data = json.loads(original)
                data['packages']['node_modules/deepmerge']['integrity'] = 'sha512-invalid'
                changed = json.dumps(data).encode()
            else:
                changed = original + b' '
            path.write_bytes(changed)
            result = verify()
            assert result.returncode != 0 and b'AssertionError' in result.stderr, name
            refused.append(name)
        finally:
            path.write_bytes(original)
    assert verify().returncode == 0
    js = r"""
const assert = require('node:assert/strict');
for (const name of ['deepmerge', 'deepmerge/dist/umd.js']) {
  const merge = require(name);
  const target = JSON.parse('{"__proto__":{"tainted":true},"safe":2}');
  const result = merge(target, {other:3});
  assert.equal(Object.prototype.hasOwnProperty.call(result, '__proto__'), false);
  assert.equal(result.tainted, undefined);
  assert.equal(Object.prototype.tainted, undefined);
  assert.deepEqual({safe:result.safe, other:result.other}, {safe:2, other:3});
}
"""
    subprocess.run(['node', '-e', js], cwd=ROOT, timeout=30, check=True)
    assert not STATE.exists()
    STATE.mkdir(mode=0o700, parents=True)
    (STATE/'tamper.json').write_text(json.dumps(refused)+'\n', encoding='utf8')
    print('all seven exact tamper cases refused; CJS and UMD regression controls passed')


def finish():
    source = source_check()
    assert verify().returncode == 0
    assert json.loads((STATE/'tamper.json').read_text(encoding='utf8')) == list(CASES)
    source.update({'status':'passed', 'tamperRefusals':list(CASES),
                   'prototypeControls':['cjs', 'umd'],
                   'nodeVersion':run('node', '--version'),
                   'npmVersion':run('npm', '--version'),
                   'hostedBuildOrSignedSdkQualified':False})
    (STATE/'result.json').write_text(json.dumps(source, sort_keys=True, indent=2)+'\n',
                                     encoding='utf8')
    print(json.dumps(source, sort_keys=True))


assert len(sys.argv) == 2 and sys.argv[1] in ('source', 'tamper', 'final')
if sys.argv[1] == 'source':
    print(json.dumps(source_check(), sort_keys=True))
elif sys.argv[1] == 'tamper':
    tamper_check()
else:
    finish()
