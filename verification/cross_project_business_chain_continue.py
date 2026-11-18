#!/usr/bin/env python3
"""Root-authorized point continuation of the retained actual fixture.

The shared driver accepts only the original known observational404 failure,
positively stopped actors and paused zero-resource authority. It resumes the
remaining existing queue's drain/refill, preserving previous completed work.
"""
import sys
sys.dont_write_bytecode = True
from cross_project_business_chain import main

if __name__ == "__main__":
    if "--resume-from-report" not in sys.argv:
        raise SystemExit("Point continuation requires the retained --resume-from-report identity")
    sys.exit(main())
