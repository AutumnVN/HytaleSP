package main

import (
	"os"
	"path/filepath"
)

var HOME_FOLDER, _ = os.UserHomeDir();

func MainFolder() string {
	return filepath.Join(HOME_FOLDER, "hytLauncher");;
}

func DefaultGameFolder() string {
	return filepath.Join(MainFolder(), "game", "versions");
}

func GameFolder() string {
	_, err := os.Stat(wCommune.GameFolder);
	if err != nil {
		return DefaultGameFolder();
	}

	return wCommune.GameFolder;
}




func UserDataFolder() string {
	return filepath.Join(MainFolder(), "userdata");
}

func LauncherFolder() string {
	return filepath.Join(MainFolder(), "launcher");
}

func JreFolder() string {
	return filepath.Join(MainFolder(), "jre");
}
func ServerDataFolder() string {
	return filepath.Join(MainFolder(), "serverdata");
}
