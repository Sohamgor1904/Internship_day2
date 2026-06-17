import { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { Shield, Menu, X } from "lucide-react";
import { buttonVariants } from "@/components/ui/button";

export function Navbar() {
  const [isScrolled, setIsScrolled] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  useEffect(() => {
    const handleScroll = () => {
      if (window.scrollY > 20) {
        setIsScrolled(true);
      } else {
        setIsScrolled(false);
      }
    };
    window.addEventListener("scroll", handleScroll);
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  const navLinks = [
    { label: "Dashboard", path: "/dashboard" },
    { label: "Alerts", path: "/alerts" },
    { label: "Anomalies", path: "/anomalies" },
    { label: "DLQ", path: "/dlq" },
    { label: "Model Performance", path: "/performance" },
  ];

  return (
    <header 
      className={`fixed top-0 left-0 right-0 z-50 transition-all duration-300 ${
        isScrolled 
          ? "bg-slate-950/90 backdrop-blur-md border-b border-slate-800 py-3 shadow-md" 
          : "bg-transparent py-5"
      }`}
    >
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex items-center justify-between">
        {/* Logo */}
        <Link to="/" className="flex items-center gap-2 font-bold text-xl text-white tracking-wider">
          <Shield className="w-6 h-6 text-indigo-400 fill-indigo-400/20 animate-pulse" />
          <span>THREAT<span className="text-indigo-400">PULSE</span></span>
        </Link>

        {/* Desktop Navigation */}
        <nav className="hidden md:flex items-center gap-8">
          {navLinks.map((link) => (
            <Link 
              key={link.path}
              to={link.path}
              className="text-sm font-medium text-slate-300 hover:text-indigo-400 transition-colors"
            >
              {link.label}
            </Link>
          ))}
          <Link 
            to="/dashboard"
            className={buttonVariants({ variant: "default", size: "sm", className: "bg-indigo-600 hover:bg-indigo-700 text-white" })}
          >
            Enter Dashboard
          </Link>
        </nav>

        {/* Mobile menu toggle */}
        <div className="md:hidden">
          <button
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className="text-slate-300 hover:text-white p-1"
          >
            {mobileMenuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
          </button>
        </div>
      </div>

      {/* Mobile drop down menu */}
      {mobileMenuOpen && (
        <div className="md:hidden bg-slate-950/95 backdrop-blur-md border-b border-slate-800 py-4 px-4 space-y-3">
          {navLinks.map((link) => (
            <Link
              key={link.path}
              to={link.path}
              onClick={() => setMobileMenuOpen(false)}
              className="block text-base font-medium text-slate-300 hover:text-indigo-400 py-2 border-b border-slate-900"
            >
              {link.label}
            </Link>
          ))}
          <Link
            to="/dashboard"
            onClick={() => setMobileMenuOpen(false)}
            className="block text-center w-full bg-indigo-600 hover:bg-indigo-700 text-white font-medium py-2.5 rounded-md"
          >
            Enter Dashboard
          </Link>
        </div>
      )}
    </header>
  );
}
