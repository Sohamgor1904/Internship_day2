import sys
import os

# Resolve project root (parent directory of scripts/) and add to PYTHONPATH
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.append(project_root)

from src.reporting.generator import generate_pdf_report

def main():
    print("==================================================")
    print("    HYBRID THREAT DETECTION PDF REPORT GENERATOR  ")
    print("==================================================")
    
    try:
        # Save output to outputs/ directory inside the project root
        output_path = os.path.join(project_root, "outputs", "Model_Performance_Report.pdf")
        generate_pdf_report(output_pdf_path=output_path)
        print("\n[SUCCESS] PDF compiled perfectly! You can find the file at:")
        print(f"  {output_path}")
    except Exception as e:
        print(f"\n[ERROR] Failed to compile PDF: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
