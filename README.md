# vault_7

OpenGL/GLFW demo vault application.

Demo credentials:
- Master password: `ilovetohatethat`
- Decryption key for entries: `turndownforwhat`

## Build (CMake)
Requirements:
- CMake ≥ 3.16
- Compiler: MSVC (Windows), Clang/Xcode (macOS), GCC/Clang (Linux)
- Linux packages (Ubuntu): `sudo apt-get install -y xorg-dev libxrandr-dev libxinerama-dev libxcursor-dev libxi-dev libgl1-mesa-dev`

Commands:
```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release --parallel
# Windows executable: build/Release/vault_7.exe
# macOS/Linux: build/vault_7
```

Data directory created at runtime:
```
vault_data/
  Passwords/
  BackupCodes/
  Notes/
```

Controls:
- Mouse: buttons + text inputs
- Paste: Ctrl+V / Cmd+V
- ESC: Back / Exit
