import Cocoa
import CoreServices

final class Guardian: NSObject, NSApplicationDelegate {
    var item: NSStatusItem!
    var running = false
    var lastStart = Date.distantPast
    var pending = false
    var stream: FSEventStreamRef?
    let base = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/Mars Item Guardian")
    func applicationDidFinishLaunching(_ notification: Notification) {
        item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        item.button?.title = "命名 ◷"
        let menu = NSMenu()
        menu.addItem(withTitle: "打开项目用途与变更看板", action: #selector(openReport), keyEquivalent: "").target = self
        menu.addItem(withTitle: "立即核查", action: #selector(manualScan), keyEquivalent: "").target = self
        menu.addItem(withTitle: "打开覆盖范围说明", action: #selector(openCoverage), keyEquivalent: "").target = self
        menu.addItem(.separator())
        menu.addItem(withTitle: "退出本次运行（下次登录恢复）", action: #selector(quit), keyEquivalent: "").target = self
        item.menu = menu
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let paths = ["/Applications", home+"/Applications", home+"/Library/LaunchAgents", "/Library/LaunchAgents", "/Library/LaunchDaemons", "/Library/Audio/Plug-Ins", "/Library/SystemExtensions", home+"/Library/Services", "/Library/Services", "/private/var/db/com.apple.backgroundtaskmanagement"]
        var context = FSEventStreamContext(version: 0, info: Unmanaged.passUnretained(self).toOpaque(), retain: nil, release: nil, copyDescription: nil)
        stream = FSEventStreamCreate(nil, { _, info, _, _, _, _ in
            guard let info = info else { return }
            let app = Unmanaged<Guardian>.fromOpaque(info).takeUnretainedValue()
            DispatchQueue.main.async { app.changed() }
        }, &context, paths as CFArray, FSEventStreamEventId(kFSEventStreamEventIdSinceNow), 3, FSEventStreamCreateFlags(kFSEventStreamCreateFlagUseCFTypes))
        if let stream = stream {
            FSEventStreamSetDispatchQueue(stream, DispatchQueue.main)
            if !FSEventStreamStart(stream) { item.button?.toolTip = "文件事件监听不可用；每5分钟巡检仍生效" }
        }
        Timer.scheduledTimer(withTimeInterval: 300, repeats: true) { _ in self.scan() }
        scan()
    }
    func changed() {
        guard !pending else { return }
        pending = true
        let delay = max(3, 60 - Date().timeIntervalSince(lastStart))
        DispatchQueue.main.asyncAfter(deadline: .now()+delay) { self.pending = false; self.scan() }
    }
    @objc func manualScan() { scan() }
    func scan() {
        guard !running else { return }
        running = true; lastStart = Date(); item.button?.title = "命名 ◷"
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        process.arguments = [base.appendingPathComponent("guardian.py").path, "scan"]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        process.terminationHandler = { task in DispatchQueue.main.async {
            self.running = false
            if task.terminationStatus != 0 { self.item.button?.title = "命名 !"; self.item.button?.toolTip = "核查失败；现有项目未被修改"; return }
            let file = self.base.appendingPathComponent("待核查.json")
            let data = try? Data(contentsOf: file)
            let entries = data.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String:Any] }
            let count = entries?.count ?? 0
            self.item.button?.title = count == 0 ? "命名 ✓" : "命名 · \(count)"
            self.item.button?.toolTip = "最近核查完成：\(DateFormatter.localizedString(from: Date(), dateStyle: .short, timeStyle: .short))；\(count)条累计变更；覆盖限制见看板"
        }}
        do { try process.run() } catch { running = false; item.button?.title = "命名 !" }
        DispatchQueue.main.asyncAfter(deadline: .now()+180) { if process.isRunning { process.terminate() } }
    }
    @objc func openReport() { NSWorkspace.shared.open(base.appendingPathComponent("项目用途看板.html")) }
    @objc func openCoverage() { NSWorkspace.shared.open(base.appendingPathComponent("coverage.json")) }
    @objc func quit() { NSApp.terminate(nil) }
}
let app = NSApplication.shared
let delegate = Guardian()
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()
