@echo off
echo Building Simple Single-Threaded Packet Analyzer...
cl /EHsc /std:c++17 /O2 /I include /Fe:dpi_engine_simple.exe src\main_working.cpp src\pcap_reader.cpp src\packet_parser.cpp src\sni_extractor.cpp src\types.cpp

if %errorlevel% neq 0 (
    echo Build failed. Make sure you run this in a Developer Command Prompt.
    exit /b %errorlevel%
)

echo running test...
dpi_engine_simple.exe test_dpi.pcap simple_output.pcap
echo Done!
