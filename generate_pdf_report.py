import sys
import os

# Add current workspace root to PYTHONPATH so we can import src modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.reporting.generator import generate_pdf_report

def main():
    print("==================================================")
    print("    HYBRID THREAT DETECTION PDF REPORT GENERATOR  ")
    print("==================================================")
    
    try:
        generate_pdf_report()
        print("\n[SUCCESS] PDF compiled perfectly! You can find the file at:")
        print("  ./outputs/Model_Performance_Report.pdf")
    except Exception as e:
        print(f"\n[ERROR] Failed to compile PDF: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
