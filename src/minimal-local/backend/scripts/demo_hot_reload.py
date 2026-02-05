#!/usr/bin/env python3
"""
Demonstration of configuration hot-reload functionality

This script starts the file watcher and monitors for changes to sources.yaml.
When the file is modified, it automatically reloads the configuration.

Usage:
    python backend/scripts/demo_hot_reload.py

Then in another terminal, modify config/sources.yaml to see the reload in action.
"""

import asyncio
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from services.source_manager import SourceManager


async def on_reload():
    """Callback function called when configuration is reloaded"""
    print("\n🔄 Configuration reloaded! Callback triggered.")


async def main():
    """Run the hot-reload demonstration"""
    print("=" * 70)
    print("Source Manager Hot-Reload Demonstration")
    print("=" * 70)
    print()
    print("This script monitors config/sources.yaml for changes.")
    print("When you modify the file, it will automatically reload.")
    print()
    print("To test:")
    print("  1. Keep this script running")
    print("  2. In another terminal, edit config/sources.yaml")
    print("  3. Save the file and watch the reload happen here")
    print()
    print("Press Ctrl+C to stop")
    print("=" * 70)
    print()
    
    # Initialize source manager
    manager = SourceManager(config_path="config/sources.yaml")
    manager.load_sources()
    
    # Register reload callback
    manager.register_reload_callback(on_reload)
    
    # Display initial state
    stats = manager.get_stats()
    print(f"Initial state:")
    print(f"  Total sources: {stats['total']}")
    print(f"  Enabled: {stats['enabled']}")
    print(f"  By type: {stats['by_type']}")
    print()
    print("Watching for changes...")
    print()
    
    # Start file watcher
    manager.start_watching()
    
    try:
        # Keep the script running
        while True:
            await asyncio.sleep(1)
            
            # Periodically show current stats
            if manager.has_config_changed():
                stats = manager.get_stats()
                print(f"\n📊 Current stats:")
                print(f"  Total sources: {stats['total']}")
                print(f"  Enabled: {stats['enabled']}")
                print(f"  By type: {stats['by_type']}")
    
    except KeyboardInterrupt:
        print("\n\n⏹️  Stopping file watcher...")
        manager.stop_watching()
        print("✓ Stopped")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\nExiting...")
        sys.exit(0)
