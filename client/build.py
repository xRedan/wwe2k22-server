"""Build/package a native client separately; never install or start the game."""
import argparse
import hashlib
import json
import os
import tempfile
from pathlib import Path
import re
import subprocess
import zipfile
ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / 'src'
TARGET = 'cf1ed48636f425a80ceb22c64341b4e3b31c9677a4e2b1b1a08fe66c2e0e7766'
VERSION = '2026.10.26-client.2'
RUNTIME_FILES = ('dinput8.dll', 'wwe2k22-private.ini')
LICENSE_FILES = ('THIRD-PARTY-NOTICES.txt', 'MINHOOK-LICENSE.txt', 'LLVM-MINGW-LICENSE.txt')
PACKAGE_FILES = RUNTIME_FILES + LICENSE_FILES + ('manifest.json',)

def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def build(output, compiler, target_sha=TARGET, test_only=False, *, sanitizer=None):
    output = Path(output).resolve()
    compiler = Path(compiler).resolve()
    if sanitizer not in (None, 'address'):
        raise ValueError('Unknown sanitizer')
    if sanitizer is not None and not test_only:
        raise ValueError('Sanitizers are restricted to owned-test builds')
    if sanitizer == 'address' and not compiler.with_name('libclang_rt.asan_dynamic-x86_64.dll').is_file():
        raise FileNotFoundError('The selected toolchain has no x64 AddressSanitizer runtime DLL')
    if not any((output.is_relative_to(ROOT / name) for name in ('build', 'dist'))):
        raise ValueError('Output must be under repository build/ or dist/')
    if not re.fullmatch('[0-9a-f]{64}', target_sha):
        raise ValueError('Invalid executable digest')
    if target_sha != TARGET and (not test_only):
        raise ValueError('Production executable digest is fixed')
    if not compiler.is_file():
        raise FileNotFoundError(compiler)
    vendor = ROOT / 'third_party/minhook'
    lock = json.loads((ROOT / 'dependencies.lock.json').read_text(encoding='utf-8'))
    for name, digest in lock['files'].items():
        if sha(vendor / name) != digest:
            raise ValueError('Vendored MinHook digest mismatch: ' + name)
    output.mkdir(parents=True, exist_ok=True)
    c_compiler = compiler.with_name(compiler.name.replace('clang++', 'clang'))
    if c_compiler == compiler or not c_compiler.is_file():
        raise ValueError('A paired LLVM-MinGW clang/clang++ toolchain is required')
    flags = ['-O2', '-Wall', '-Wextra', '-Werror', '-fstack-protector-strong',
             '-D_WIN32_WINNT=0x0602', '-ffile-prefix-map=' + str(ROOT) + '=client',
             '-fmacro-prefix-map=' + str(ROOT) + '=client', '-I' + str(vendor / 'include')]
    if sanitizer == 'address':
        flags += ['-fsanitize=address', '-fno-omit-frame-pointer', '-gline-tables-only']
    build_root = (ROOT / 'build').resolve()
    if not build_root.is_relative_to(ROOT):
        raise ValueError('Build directory resolves outside repository')
    build_root.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='native-build-', dir=build_root) as scratch:
        if not Path(scratch).resolve().is_relative_to(build_root):
            raise ValueError('Unexpected scratch directory')
        objects_dir = Path(scratch)
        objects = []
        for name in ('buffer.c', 'hook.c', 'trampoline.c', 'hde/hde64.c'):
            source = vendor / 'src' / name
            target = objects_dir / (source.stem + '.o')
            subprocess.run([str(c_compiler), *flags, '-c', str(source), '-o', str(target)], check=True)
            objects.append(str(target))
        command = [str(compiler), '-std=c++17', *flags, '-shared',
                   *(['-shared-libasan'] if sanitizer == 'address' else ['-static']),
                   '-fstack-protector-strong', '-DWWE_TARGET_SHA256="' + target_sha + '"']
        if test_only:
            command += ['-DWWE_OWNED_TEST', '-Wno-unused-function', '-Wno-unused-variable']
        command += [str(SOURCE / name) for name in ('loader.cpp', 'config.cpp', 'runtime.cpp', 'integrity.cpp', 'logging.cpp', 'publication.cpp', 'image_sync.cpp', 'hooks.cpp', 'cleanup.cpp', 'http.cpp', 'game.cpp', 'lobby_search.cpp', 'diagnostics.cpp', 'entry.S', 'dinput8.def')]
        command += objects + ['-lwinhttp', '-lbcrypt', '-Wl,--no-insert-timestamp,--dynamicbase,--nxcompat,--high-entropy-va', '-o', str(objects_dir / 'dinput8.dll')]
        subprocess.run(command, check=True)
        os.replace(objects_dir / 'dinput8.dll', output / 'dinput8.dll')
    atomic_write(output / 'wwe2k22-private.ini', (ROOT / 'config/wwe2k22-private.ini').read_bytes())
    atomic_write(output / 'THIRD-PARTY-NOTICES.txt', (ROOT / 'third_party/NOTICES.txt').read_bytes())
    atomic_write(output / 'MINHOOK-LICENSE.txt', (vendor / 'LICENSE.txt').read_bytes())
    atomic_write(output / 'LLVM-MINGW-LICENSE.txt', (ROOT / 'third_party/LLVM-MINGW-LICENSE.txt').read_bytes())
    manifest = {
        'version': VERSION, 'kind': 'owned-test-native-client' if test_only else 'native-client',
        'target_sha256': target_sha, 'target_profile': 'WWE2K22-PC-1.21-pinned',
        'gameplay_verified': False, 'runtime_files': list(RUNTIME_FILES),
        'package_files': list(PACKAGE_FILES), 'hook_library': 'MinHook 1.3.4',
        'files': {name: {'sha256': sha(output / name), 'bytes': (output / name).stat().st_size}
                  for name in RUNTIME_FILES + LICENSE_FILES},
        'source_sha256': {path.relative_to(ROOT).as_posix(): sha(path)
                          for path in sorted(SOURCE.rglob('*'))
                          if path.is_file() and path.suffix in ('.cpp', '.hpp', '.S', '.c', '.h', '.def')},
    }
    if sanitizer is not None:
        manifest['sanitizer'] = sanitizer
    atomic_write(output / 'manifest.json', (json.dumps(manifest, indent=2) + '\n').encode('utf-8'))
    return manifest

def atomic_write(path, data):
    """Keep the previous file if writing or replacement fails."""
    path = Path(path)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(prefix=path.name + '.', suffix='.tmp', dir=path.parent, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(data)
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)

def package(output, archive):
    """Validate one byte snapshot and publish the complete archive atomically."""
    output = Path(output).resolve()
    archive = Path(archive).resolve()
    if not archive.is_relative_to(ROOT / 'dist'):
        raise ValueError('Archive must remain under repository dist/')
    if archive in {output / name for name in PACKAGE_FILES}:
        raise ValueError('Archive overlaps a bundle input file')
    payloads = {name: (output / name).read_bytes() for name in PACKAGE_FILES}
    manifest = json.loads(payloads['manifest.json'])
    if manifest.get('kind') != 'native-client' or manifest.get('target_sha256') != TARGET:
        raise ValueError('Cannot package an owned-test or unknown executable build')
    if set(manifest.get('files', {})) != set(RUNTIME_FILES + LICENSE_FILES):
        raise ValueError('Manifest does not describe the exact allowed bundle')
    if manifest.get('runtime_files') != list(RUNTIME_FILES) or manifest.get('package_files') != list(PACKAGE_FILES):
        raise ValueError('Manifest file lists do not match this package format')
    for name, record in manifest['files'].items():
        if hashlib.sha256(payloads[name]).hexdigest() != record['sha256'] or len(payloads[name]) != record['bytes']:
            raise ValueError('Modified bundle file: ' + name)
    archive.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(prefix=archive.name + '.', suffix='.tmp', dir=archive.parent, delete=False) as stream:
            temporary = Path(stream.name)
        with zipfile.ZipFile(temporary, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as bundle:
            for name in PACKAGE_FILES:
                entry = zipfile.ZipInfo('wwe2k22-client/' + name, (2026, 10, 24, 0, 0, 0))
                entry.compress_type = zipfile.ZIP_DEFLATED
                entry.external_attr = 420 << 16
                bundle.writestr(entry, payloads[name])
        os.replace(temporary, archive)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', required=True, type=Path)
    parser.add_argument('--output', type=Path, default=ROOT / 'dist')
    args = parser.parse_args()
    build(args.output, args.compiler)
    archive = ROOT / 'dist/wwe2k22-client.zip'
    package(args.output, archive)
    print(json.dumps({'output': str(args.output), 'archive': str(archive), 'game_started': False}))
if __name__ == '__main__':
    main()
