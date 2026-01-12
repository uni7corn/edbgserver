use std::{
    fs::{self, File},
    io,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, anyhow, bail};
use goblin::elf::Elf;
use log::{debug, info};
use zip::ZipArchive;

/// Resolve the target library path and break point offset for uprobe to attach.
/// Returns a tuple of (library_path, resolved_file_offset).
pub fn resolve_target(
    target: &str,
    package: Option<&str>,
    break_point: u64,
) -> Result<(PathBuf, u64)> {
    let library_path = if let Some(pkg_name) = package {
        let apk_path = find_apk_path_for_package(pkg_name)
            .context(format!("Could not find APK for package: {}", pkg_name))?;

        info!("Found APK for package {}: {:?}", pkg_name, apk_path);

        if let Some(extracted_path) = try_find_extracted_library(&apk_path, target) {
            info!("Found extracted library on disk: {:?}", extracted_path);
            extracted_path
        } else {
            let out_path = extract_so_from_apk(&apk_path, target)
                .context("Failed to extract native library from APK")?;
            info!("Extracted {} to {:?}", target, out_path);
            out_path
        }
    } else {
        PathBuf::from(target)
    };

    let file_offset = translate_vaddr_to_offset(&library_path, break_point)
        .context("Failed to resolve virtual address to file offset")?;

    info!(
        "Resolved breakpoint: 0x{:x} (Virtual) -> 0x{:x} (Offset)",
        break_point, file_offset
    );

    Ok((library_path, file_offset))
}

fn translate_vaddr_to_offset(path: &Path, vaddr: u64) -> Result<u64> {
    let buffer = fs::read(path).context("Failed to read ELF file for parsing")?;

    let elf = Elf::parse(&buffer).context("Failed to parse ELF headers")?;

    for ph in elf.program_headers {
        if ph.p_type == goblin::elf::program_header::PT_LOAD {
            // [p_vaddr, p_vaddr + p_memsz)
            if vaddr >= ph.p_vaddr && vaddr < (ph.p_vaddr + ph.p_memsz) {
                // File Offset = Target VAddr - Segment VAddr + Segment File Offset
                let offset = vaddr - ph.p_vaddr + ph.p_offset;
                debug!(
                    "Found address 0x{:x} in segment [VAddr: 0x{:x}, Offset: 0x{:x}]. Calculated offset: 0x{:x}",
                    vaddr, ph.p_vaddr, ph.p_offset, offset
                );
                return Ok(offset);
            }
        }
    }

    bail!(
        "Address 0x{:x} is not within any LOAD segment of the ELF file. Please ensure you are using a Virtual Address (from readelf/nm).",
        vaddr
    );
}

fn try_find_extracted_library(apk_path: &Path, so_name: &str) -> Option<PathBuf> {
    let extracted_path = apk_path.parent()?.join("lib").join("arm64").join(so_name);
    debug!("Checking for extracted library at {:?}", extracted_path);
    if extracted_path.exists() {
        Some(extracted_path)
    } else {
        None
    }
}

fn find_apk_path_for_package(package: &str) -> Result<PathBuf> {
    let output = Command::new("pm").arg("path").arg(package).output()?;
    let out_str = String::from_utf8(output.stdout)?;
    // pm path output: package:/data/app/~~.../base.apk
    let path_str = out_str
        .trim()
        .strip_prefix("package:")
        .ok_or_else(|| anyhow!("Unexpected output from pm path: {}", out_str))?;

    Ok(PathBuf::from(path_str))
}

fn extract_so_from_apk(apk_path: &Path, so_name: &str) -> Result<PathBuf> {
    let file = File::open(apk_path).context("Open APK failed")?;
    let mut archive = ZipArchive::new(file).context("Parse ZIP failed")?;
    let target_in_zip = format!("lib/arm64-v8a/{}", so_name);
    let out_path = apk_path
        .parent()
        .ok_or_else(|| anyhow!("Invalid APK path"))?
        .join("lib")
        .join("arm64")
        .join(so_name);

    let mut zip_file = archive
        .by_name(&target_in_zip)
        .context(format!("'{}' not found in APK", target_in_zip))?;

    let mut out_file =
        File::create(&out_path).context(format!("Failed to create output file: {:?}", out_path))?;

    io::copy(&mut zip_file, &mut out_file).context("Failed to decompress file")?;

    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(&out_path)?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&out_path, perms)?;

    Ok(out_path)
}

// fn find_so_offset_in_apk(apk_path: &Path, so_name: &str) -> Result<u64> {
//     let file = File::open(apk_path).context("Open APK failed")?;
//     let mut archive = ZipArchive::new(file).context("Parse ZIP failed")?;
//     let target_path = format!("lib/arm64-v8a/{}", so_name);
//     let file = archive
//         .by_name(&target_path)
//         .context(format!("'{}' not found in APK", target_path))?;
//     if file.compression() != zip::CompressionMethod::Stored {
//         bail!("Library is compressed! offset is invalid for mmap.");
//     }
//     Ok(file.data_start())
// }
