package hooks

import "fmt"

func InstallAll() error {
	rc := nativeInstallAll()
	if rc != 0 {
		return fmt.Errorf("install native hooks: errno %d", -rc)
	}
	return nil
}

func RemoveAll() error {
	rc := nativeRemoveAll()
	if rc != 0 {
		return fmt.Errorf("remove native hooks: errno %d", -rc)
	}
	return nil
}
