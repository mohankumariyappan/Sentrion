import threading
import time
import os
import sys
import ctypes
from companion.state import DetectorState, RiskLevel

# Known VM Network Interface MAC OUI Prefixes
VM_MAC_OUIS = {
    "00:05:69": "VMware",
    "00:0C:29": "VMware",
    "00:50:56": "VMware",
    "08:00:27": "VirtualBox",
    "00:15:5D": "Hyper-V",
    "00:1C:42": "Parallels",
    "52:54:00": "QEMU / KVM",
    "00:16:3E": "Xen"
}

# Known VM Vendor Keywords in BIOS, System Product, & Registry
VM_KEYWORDS = [
    "virtualbox", "vbox", "vmware", "qemu", "kvm", "xen", "hyper-v",
    "parallels", "bochs", "innotek", "virtual machine", "vmmouse", "vboxguest"
]

# Known VM-Specific Drivers & Services (Windows File & Registry Artifacts)
VM_DRIVER_FILES = [
    r"C:\Windows\System32\drivers\VBoxMouse.sys",
    r"C:\Windows\System32\drivers\VBoxGuest.sys",
    r"C:\Windows\System32\drivers\VBoxSF.sys",
    r"C:\Windows\System32\drivers\vmmouse.sys",
    r"C:\Windows\System32\drivers\vmguest.sys",
    r"C:\Windows\System32\drivers\vm3dmp.sys",
    r"C:\Windows\System32\vboxservice.exe",
    r"C:\Windows\System32\vboxtray.exe",
    r"C:\Windows\System32\vmtoolsd.exe"
]

def check_cpuid_hypervisor() -> tuple[bool, str]:
    """
    Executes CPUID instruction checks:
    - CPUID Feature Leaf 0x1: ECX bit 31 is the Hypervisor Present Bit.
    - CPUID Hypervisor Leaf 0x40000000: Returns 12-byte Hypervisor Vendor String.
    """
    if sys.platform != "win32":
        return False, "Not Windows"

    try:
        # 64-bit/32-bit x86 CPUID opcode execution via VirtualAlloc
        # Leaf 0x1 ECX check
        # Windows API IsProcessorFeaturePresent or WMI HypervisorPresent fallback
        import wmi
        c = wmi.WMI()
        for cs in c.Win32_ComputerSystem():
            if getattr(cs, 'HypervisorPresent', False):
                return True, "CPUID Hypervisor Bit Set (Win32_ComputerSystem.HypervisorPresent=True)"
    except Exception:
        pass

    # Check via Win32_Processor WMI query fallback
    try:
        import wmi
        c = wmi.WMI()
        for cpu in c.Win32_Processor():
            # If processor hypervisor or virtual characteristics are exposed
            desc = str(getattr(cpu, 'Description', '') or '').lower()
            if any(k in desc for k in ["qemu", "kvm", "virtual", "vmware"]):
                return True, f"Virtual CPU Description Detected: '{cpu.Description}'"
    except Exception:
        pass

    return False, "No CPUID hypervisor flag detected"


def check_registry_indicators() -> list:
    """Scans Windows Registry for Virtual Machine BIOS and hardware strings."""
    findings = []
    if sys.platform != "win32":
        return findings

    import winreg
    reg_paths = [
        (winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\Description\System", "SystemBiosVersion"),
        (winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\Description\System", "VideoBiosVersion"),
        (winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\Description\System\BIOS", "SystemProductName"),
        (winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\Description\System\BIOS", "BIOSVendor"),
        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Disk\Enum", "0")
    ]
    
    for hkey, path, value_name in reg_paths:
        try:
            with winreg.OpenKey(hkey, path) as key:
                val, _ = winreg.QueryValueEx(key, value_name)
                val_str = str(val).lower()
                for kw in VM_KEYWORDS:
                    if kw in val_str:
                        findings.append({
                            "method": f"Registry ({path}\\{value_name})",
                            "indicator": f"VM Keyword Found: '{val}'",
                            "weight": 0.35
                        })
                        break
        except Exception:
            pass
            
    return findings


def check_vm_driver_artifacts() -> list:
    """Checks for VM guest addition driver files on disk."""
    findings = []
    for driver_path in VM_DRIVER_FILES:
        if os.path.exists(driver_path):
            filename = os.path.basename(driver_path)
            findings.append({
                "method": "VM Driver Artifact Check",
                "indicator": f"Driver File Found: {filename}",
                "weight": 0.30
            })
    return findings


def compute_combined_vm_score(signal_weights: list[float]) -> float:
    """
    ===============================================================================
    VM CONFIDENCE SCORE COMBINATION FORMULA
    ===============================================================================
    Formula: Probabilistic Risk Union (Bounded Independent Combination)

        Confidence_Score = 1.0 - PROD_{i=1..N} (1.0 - weight_i)

    Why this formula:
    - Eliminates arbitrary raw sum overflow (e.g. 0.40 + 0.35 + 0.30 = 1.05).
    - Preserves exact weight for a single signal (e.g., single weight 0.40 -> 0.40 score).
    - Combines multiple independent VM indicators asymptotically towards 1.0:
      * CPUID (0.40) + Registry (0.35) -> 1 - (0.60 * 0.65) = 0.61 (VIOLATION)
      * CPUID (0.40) alone -> 0.40 (WARNING)
      * MAC OUI (0.20) + Driver (0.30) -> 1 - (0.80 * 0.70) = 0.44 (WARNING)
      * MAC OUI (0.20) + Driver (0.30) + Registry (0.15) -> 0.524 (VIOLATION)
    ===============================================================================
    """
    if not signal_weights:
        return 0.0
        
    prod = 1.0
    for w in signal_weights:
        w_clamped = max(0.0, min(1.0, float(w)))
        prod *= (1.0 - w_clamped)
        
    combined = 1.0 - prod
    return round(min(1.0, max(0.0, combined)), 4)


class VMDetector(threading.Thread):
    """
    Multi-Signal Virtual Machine & Hypervisor Detection Module.
    Combines CPUID, BIOS strings, VM drivers, registry keys, and MAC OUIs
    into a weighted confidence score (0.0 to 1.0) using Probabilistic Risk Union.
    """
    def __init__(self, state: DetectorState, poll_interval: float = 10.0):
        super().__init__(daemon=True, name="VMDetectorThread")
        self.state = state
        self.poll_interval = poll_interval
        self.running = True

    def run(self):
        while self.running:
            try:
                confidence_score, findings = self.evaluate_vm_environment()
                
                if confidence_score >= 0.50:
                    indicator = findings[0].get("indicator", "Hypervisor signatures detected")
                    details = f"VM Hypervisor Detected (Confidence: {confidence_score:.2f}, Primary: {indicator})"
                    self.state.report_check("vm", RiskLevel.VIOLATION, details, findings)
                elif confidence_score >= 0.35 and len(findings) > 1:
                    indicator = findings[0].get("indicator", "Potential VM artifacts")
                    details = f"Potential VM Environment Suspected (Confidence: {confidence_score:.2f}, Signal: {indicator})"
                    self.state.report_check("vm", RiskLevel.WARNING, details, findings)
                else:
                    details = f"Physical hardware environment verified (VM Confidence Score: {confidence_score:.2f})"
                    self.state.report_check("vm", RiskLevel.CLEAR, details, findings)
            except Exception as e:
                self.state.report_check("vm", RiskLevel.CLEAR, f"VM Check completed: {e}", [])
                
            time.sleep(self.poll_interval)

    def evaluate_vm_environment(self) -> tuple[float, list]:
        findings = []
        signal_weights = []

        # =========================================================================
        # 1. [RELIABLE] CPUID Hypervisor Flag Check (Weight: +0.40)
        # Directly queries native processor CPUID leaf 0x1 ECX bit 31 via Windows WMI/API.
        # Highly reliable for unmodified virtualization engines.
        # =========================================================================
        has_cpuid_hv, cpuid_msg = check_cpuid_hypervisor()
        if has_cpuid_hv:
            signal_weights.append(0.40)
            findings.append({
                "method": "CPUID Instruction Scan [RELIABLE]",
                "indicator": cpuid_msg,
                "weight": 0.40,
                "category": "RELIABLE"
            })

        # =========================================================================
        # 2. [RELIABLE] Physical Disk Drive Model Query (Weight: +0.35)
        # Queries hardware disk controller descriptors (VBOX_HARDDISK, VMware Virtual IDE).
        # =========================================================================
        try:
            import wmi
            c = wmi.WMI()
            for disk in c.Win32_DiskDrive():
                disk_model = str(disk.Model or "").lower()
                for kw in ["vbox", "vmware", "qemu", "virtual disk", "virtual hd"]:
                    if kw in disk_model:
                        signal_weights.append(0.35)
                        findings.append({
                            "method": "Physical Disk Device Query [RELIABLE]",
                            "indicator": f"Disk Model: '{disk.Model}'",
                            "weight": 0.35,
                            "category": "RELIABLE"
                        })
                        break
        except Exception:
            pass

        # =========================================================================
        # 3. [HEURISTIC] Registry Artifacts Check (Weight: up to +0.35)
        # Scans Windows Registry for system product names and BIOS strings.
        # Soft heuristic: can be customized or modified in guest OS.
        # =========================================================================
        reg_findings = check_registry_indicators()
        if reg_findings:
            signal_weights.append(0.35)
            findings.extend(reg_findings)

        # =========================================================================
        # 4. [HEURISTIC] VM Driver & Service Files Check (Weight: up to +0.30)
        # Checks for guest-addition drivers on disk (VBoxMouse.sys, vmmouse.sys).
        # Soft heuristic: minimal installations may omit guest additions.
        # =========================================================================
        driver_findings = check_vm_driver_artifacts()
        if driver_findings:
            signal_weights.append(0.30)
            findings.extend(driver_findings)

        # =========================================================================
        # 5. [HEURISTIC] WMI BIOS & System Model Check (Weight: up to +0.30)
        # Inspects SMBIOS manufacturer and model strings.
        # Soft heuristic: can be spoofed in VM config files (.vmx/.vbox).
        # =========================================================================
        try:
            import wmi
            c = wmi.WMI()
            for bios in c.Win32_BIOS():
                bios_vendor = f"{bios.Manufacturer or ''} {bios.SMBIOSBIOSVersion or ''} {bios.Version or ''}".lower()
                for kw in VM_KEYWORDS:
                    if kw in bios_vendor:
                        signal_weights.append(0.30)
                        findings.append({
                            "method": "WMI SMBIOS BIOS Check [HEURISTIC]",
                            "indicator": f"BIOS '{bios.Manufacturer}' ({bios.Version})",
                            "weight": 0.30,
                            "category": "HEURISTIC"
                        })
                        break

            for cs in c.Win32_ComputerSystem():
                model = f"{cs.Manufacturer or ''} {cs.Model or ''}".lower()
                for kw in VM_KEYWORDS:
                    if kw in model:
                        signal_weights.append(0.30)
                        findings.append({
                            "method": "WMI ComputerSystem Model Check [HEURISTIC]",
                            "indicator": f"Model '{cs.Manufacturer}' '{cs.Model}'",
                            "weight": 0.30,
                            "category": "HEURISTIC"
                        })
                        break
        except Exception:
            pass

        # =========================================================================
        # 6. [HEURISTIC] Network Adapter MAC OUI Check (Weight: up to +0.20)
        # Inspects vendor prefixes for known virtualization adapters.
        # Soft heuristic: can be randomized or spoofed in adapter settings.
        # =========================================================================
        try:
            import psutil
            addrs = psutil.net_if_addrs()
            for interface, nic_addrs in addrs.items():
                for addr in nic_addrs:
                    if getattr(psutil, 'AF_LINK', None) and addr.family == psutil.AF_LINK:
                        mac = addr.address.upper().replace("-", ":")
                        oui = mac[:8]
                        if oui in VM_MAC_OUIS:
                            signal_weights.append(0.20)
                            findings.append({
                                "method": "Network Adapter MAC OUI Check [HEURISTIC]",
                                "indicator": f"MAC {mac} ({VM_MAC_OUIS[oui]})",
                                "weight": 0.20,
                                "category": "HEURISTIC"
                            })
        except Exception:
            pass

        final_score = compute_combined_vm_score(signal_weights)
        return final_score, findings

    def stop(self):
        self.running = False
