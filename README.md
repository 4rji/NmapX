**Install Go dependencies:**
   ```sh
   go mod tidy
   ```

## Usage

### Run the Full UI Scanner
```sh
sudo go run old-files/nmap-full.go <CIDR>
```

### Run the Half UI Scanner
```sh
sudo go run old-files/nmap-half.go <CIDR>
```

Replace `<CIDR>` with the target network, e.g. `192.168.1.0/24`.

## Output
- The UI will show Nmap processes, scan logs, and a live tail of the port scan results.
- When the scan finishes, an HTML report will be generated in a timestamped directory (e.g. `recon_YYYYMMDD_HHMMSS/report.html` or `test_YYYYMMDD_HHMMSS/report.html`).
- A popup will show the location of the generated report and related log files.

## Project Structure

The project has been refactored into a modular structure for better maintainability:

- `nmapx.go`: Main application entry point for the "half" UI scanner
- `nmap-full.go`: Main application entry point for the "full" UI scanner
- `utils.go`: Basic utility functions like command execution
- `ui.go`: UI setup and application state definitions
- `monitor.go`: Process monitoring and log redirection functionality
- `scanner.go`: Network scanning implementation
- `report.go`: HTML report generation and results display

This modular approach makes the codebase easier to understand and maintain, with each file having a single responsibility.

## Running the Application

After refactoring the code into multiple files, you can run the application using the following methods:

### Method 1: Run directly with Go

To run the Half UI scanner:
```sh
sudo go run nmapx.go utils.go ui.go monitor.go scanner.go report.go <CIDR>
```

To run the Full UI scanner:
```sh
sudo go run nmap-full.go utils.go ui.go monitor.go scanner.go report.go <CIDR>
```

Example (for scanning the 10.0.4.0/24 network with Half UI scanner):
```sh
sudo go run nmapx.go utils.go ui.go monitor.go scanner.go report.go 10.0.4.0/24
```

### Method 2: Run using go run with the directory

The following simplified commands may work in some environments:
```sh
sudo go run . <CIDR>  # This may not work in all cases
```

### Method 3: Compile and run as a binary

To compile the scanner:
```sh
go build -o nmapx nmapx.go utils.go ui.go monitor.go scanner.go report.go
sudo ./nmapx <CIDR>
```

For the full UI version:
```sh
go build -o nmapx nmap-full.go utils.go ui.go monitor.go scanner.go report.go
sudo ./nmapx <CIDR>
```

For all methods, replace `<CIDR>` with your target network (e.g., `192.168.1.0/24` or `10.0.4.0/24`).

Note: Running with `sudo` is required because nmap needs root privileges to perform certain types of scans.

