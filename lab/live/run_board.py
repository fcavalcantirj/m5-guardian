#!/usr/bin/env python3
"""Explicitly launched G13 scenarios. Setup/build never calls this entry point."""
from run import main,RunInterrupted
from board import BoardSession
if __name__=='__main__':
    try:raise SystemExit(main(BoardSession))
    except RunInterrupted as e:raise SystemExit(128+e.signum)
    except (ValueError,RuntimeError,OSError) as e:raise SystemExit(str(e))
