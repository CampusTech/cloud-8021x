// Development-only read-only R105 forensic runner. No network, sockets or shares.
import Foundation
import Virtualization

final class StopDelegate: NSObject, VZVirtualMachineDelegate {
    func guestDidStop(_ virtualMachine: VZVirtualMachine) {
        print("TASK11_VZ_STOPPED")
        exit(0)
    }
    func virtualMachine(_ virtualMachine: VZVirtualMachine, didStopWithError error: Error) {
        fputs("TASK11_VZ_FAILED \(error)\n", stderr)
        exit(1)
    }
}

func ownedRegularURL(_ path: String, maximum: UInt64) throws -> URL {
    let url = URL(fileURLWithPath: path).resolvingSymlinksInPath()
    let temporaryRoot = URL(fileURLWithPath: "/private/tmp").resolvingSymlinksInPath().path
    guard url.path.hasPrefix(temporaryRoot + "/cloud8021x-task11-") else {
        throw NSError(domain: "Task11", code: 1, userInfo: [NSLocalizedDescriptionKey: "Only task-owned temporary image paths are accepted"])
    }
    let values = try url.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey])
    guard values.isRegularFile == true, let size = values.fileSize, size > 0, UInt64(size) <= maximum else {
        throw NSError(domain: "Task11", code: 2, userInfo: [NSLocalizedDescriptionKey: "Image is not a bounded regular file"])
    }
    return url
}

setbuf(stdout, nil)
let args = CommandLine.arguments
guard args.count == 5 else {
    fputs("usage: zero-nic-rescue OWNED_BOOT OWNED_READONLY_SEED OWNED_EFI OWNED_READONLY_EVIDENCE\n", stderr)
    exit(2)
}
let delegate = StopDelegate()
let virtualMachine: VZVirtualMachine

do {
    let disk = try ownedRegularURL(args[1], maximum: 3221225472)
    let seed = try ownedRegularURL(args[2], maximum: 1024 * 1024)
    let efi = try ownedRegularURL(args[3], maximum: 1024 * 1024)
    let evidence = try ownedRegularURL(args[4], maximum: 8000000000)
    let identities = try [disk, seed, efi, evidence].map { url -> String in
        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        guard let device = attributes[.systemNumber] as? NSNumber,
              let inode = attributes[.systemFileNumber] as? NSNumber else {
            throw NSError(domain: "Task11", code: 4, userInfo: [NSLocalizedDescriptionKey: "File identity unavailable"])
        }
        return "\(device):\(inode)"
    }
    guard Set(identities).count == 4 else {
        throw NSError(domain: "Task11", code: 3, userInfo: [NSLocalizedDescriptionKey: "Evidence must not alias a writable attachment"])
    }
    let configuration = VZVirtualMachineConfiguration()
    configuration.cpuCount = 2
    configuration.memorySize = 3 * 1024 * 1024 * 1024
    configuration.platform = VZGenericPlatformConfiguration()
    let boot = VZEFIBootLoader()
    boot.variableStore = VZEFIVariableStore(url: efi)
    configuration.bootLoader = boot
    configuration.storageDevices = [
        VZVirtioBlockDeviceConfiguration(attachment: try VZDiskImageStorageDeviceAttachment(url: disk, readOnly: false)),
        VZVirtioBlockDeviceConfiguration(attachment: try VZDiskImageStorageDeviceAttachment(url: seed, readOnly: true)),
        VZVirtioBlockDeviceConfiguration(attachment: try VZDiskImageStorageDeviceAttachment(url: evidence, readOnly: true))
    ]
    let serial = VZVirtioConsoleDeviceSerialPortConfiguration()
    serial.attachment = VZFileHandleSerialPortAttachment(fileHandleForReading: nil, fileHandleForWriting: FileHandle.standardOutput)
    configuration.serialPorts = [serial]
    configuration.entropyDevices = [VZVirtioEntropyDeviceConfiguration()]
    configuration.networkDevices = []
    configuration.socketDevices = []
    configuration.directorySharingDevices = []
    configuration.audioDevices = []
    configuration.graphicsDevices = []
    configuration.keyboards = []
    configuration.pointingDevices = []
    try configuration.validate()
    virtualMachine = VZVirtualMachine(configuration: configuration)
    virtualMachine.delegate = delegate
    print("TASK11_VZ_CONFIG cpu=2 memory=3221225472 networkDevices=0 socketDevices=0 shares=0 readonlySeed=true readonlyEvidence=true writableBootMaximum=3221225472")
    virtualMachine.start { result in
        switch result {
        case .success: print("TASK11_VZ_STARTED")
        case .failure(let error): fputs("TASK11_VZ_START_FAILED \(error)\n", stderr); exit(1)
        }
    }
    let watchdogSeconds: Double = 240
    DispatchQueue.main.asyncAfter(deadline: .now() + watchdogSeconds) {
        fputs("TASK11_VZ_TIMEOUT\n", stderr)
        exit(2)
    }
    RunLoop.main.run()
} catch {
    fputs("TASK11_VZ_CONFIG_FAILED \(error)\n", stderr)
    exit(1)
}
