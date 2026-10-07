package wire

// APIImport is one DLL/export pair in the loader hash table.
type APIImport struct {
	Module string
	Name   string
}
