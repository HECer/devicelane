use std::fs;

#[test]
fn native_release_archives_match_the_npm_launcher_contract() {
    let workflow = fs::read_to_string(".github/workflows/release.yml").unwrap();

    for binary in [
        "devicelane",
        "devicelane-service",
        "mesh-cli",
        "mesh-agent",
        "mesh-registry",
    ] {
        assert!(
            workflow.contains(&format!("target/release/{binary}.exe")),
            "Windows package is missing {binary}.exe"
        );
    }
    assert!(
        workflow.contains(
            "-C target/release devicelane devicelane-service mesh-cli mesh-agent mesh-registry"
        ),
        "Unix package does not contain the exact native executable set"
    );
    assert!(workflow.contains("README.md,LICENSE"));
    assert!(workflow.contains("-C ../.. README.md LICENSE"));
    assert!(workflow.contains("sha256sum devicelane-* > SHA256SUMS"));
    assert!(workflow.contains("gh release create"));
    assert!(workflow.contains("dist/*"));
}
