import XCTest

final class DeviceMeshGateUITests: XCTestCase {
    func testPhysicalDeviceLaunchAndScreenshot() {
        let app = XCUIApplication()
        app.launch()
        XCTAssertTrue(app.staticTexts["mesh-gate-status"].waitForExistence(timeout: 15))
        let attachment = XCTAttachment(screenshot: XCUIScreen.main.screenshot())
        attachment.name = "physical-iphone-hardware-gate"
        attachment.lifetime = .keepAlways
        add(attachment)
    }
}
