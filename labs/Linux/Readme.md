# Microsoft Defender for Endpoint Linux Lab Tests

Reusable lab scripts for validating Microsoft Defender for Endpoint (MDE) on authorized Linux test machines.

## Included files

- `MDEHealthCheck.sh` - checks important `mdatp health` values and prints full health output.
- `EICARTest.sh` - downloads the standard EICAR antivirus test file and checks local Defender threat history.
- `EDRDetectionTest.sh` - downloads and runs Microsoft's official MDE Linux EDR DIY test package.
- `BehaviorMonitoringTest.sh` - generates benign process and file activity for telemetry review.
- `ReconTest.sh` - generates benign Linux discovery/reconnaissance activity for telemetry review.
- `LinuxTestRunner.sh` - runs the complete suite sequentially and saves a timestamped log.

## Usage

Copy the files to a dedicated, authorized Linux lab device, then run:

    chmod +x *.sh
    ./LinuxTestRunner.sh

Run individual tests the same way, for example:

    ./MDEHealthCheck.sh
    ./EICARTest.sh
    ./EDRDetectionTest.sh

## Validation philosophy

A local block, endpoint telemetry, an Advanced Hunting event, a Defender alert, and an incident are separate outcomes. Do not treat the absence of one as proof that another control failed. Record the expected outcome for each scenario, then validate the local endpoint and Microsoft Defender portal separately.

## Safety

Use only on dedicated systems and tenants where you are authorized to perform security testing. The EICAR file is a standard antivirus test file, not malware. The EDR test uses Microsoft's published Linux EDR DIY package.

## Microsoft documentation

- Microsoft Defender for Endpoint on Linux: https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-endpoint-linux
- EDR detection test: https://learn.microsoft.com/en-us/defender-endpoint/edr-detection
- Linux resources and `mdatp` CLI: https://learn.microsoft.com/en-us/defender-endpoint/linux-resources
- Agent health fields: https://learn.microsoft.com/en-us/defender-endpoint/health-status
