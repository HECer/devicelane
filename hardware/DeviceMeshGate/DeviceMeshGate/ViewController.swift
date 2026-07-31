import UIKit
import os

final class ViewController: UIViewController {
    private let logger = Logger(subsystem: "dev.mesh.hardware-gate", category: "gate")

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .systemBackground
        let label = UILabel()
        label.accessibilityIdentifier = "mesh-gate-status"
        label.text = "Device Mesh Hardware Gate Ready"
        label.font = .preferredFont(forTextStyle: .title2)
        label.textAlignment = .center
        label.numberOfLines = 0
        label.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(label)
        NSLayoutConstraint.activate([
            label.leadingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.leadingAnchor, constant: 24),
            label.trailingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.trailingAnchor, constant: -24),
            label.centerYAnchor.constraint(equalTo: view.centerYAnchor)
        ])
        logger.notice("hardware gate app launched")
        print("hardware gate app launched")
    }
}
