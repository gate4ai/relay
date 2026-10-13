// SPDX-License-Identifier: FSL-1.1-ALv2

package relay

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"time"
)

// Store — состояние relay: устройства, TXT-записи ACME, чекпоинты-свидетельства.
type Store struct {
	path string
	mu   sync.Mutex
	data storeData
}

type storeData struct {
	Devices     map[string]string                `json:"devices"` // device id → sha256(token)
	TXT         map[string][]string              `json:"txt"`     // fqdn → значения
	Checkpoints map[string][]WitnessedCheckpoint `json:"checkpoints"`
}

// WitnessedCheckpoint — чекпоинт, принятый свидетелем.
type WitnessedCheckpoint struct {
	Seq        int64     `json:"seq"`
	Head       string    `json:"head"`
	TS         time.Time `json:"ts"`
	Sig        string    `json:"sig"`
	ReceivedAt time.Time `json:"received_at"`
}

// OpenStore открывает (или создаёт) состояние в JSON-файле; path "" — только память.
func OpenStore(path string) (*Store, error) {
	s := &Store{path: path, data: storeData{Devices: map[string]string{}, TXT: map[string][]string{}, Checkpoints: map[string][]WitnessedCheckpoint{}}}
	if path == "" {
		return s, nil
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &s.data); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) save() error {
	if s.path == "" {
		return nil
	}
	b, _ := json.MarshalIndent(s.data, "", " ")
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func hashTok(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewDeviceID — случайный id устройства (имена сертификатов публичны в CT-логах).
func NewDeviceID() string {
	b := make([]byte, 10)
	_, _ = rand.Read(b)
	return strings.ToLower(b32.EncodeToString(b))
}

// Register регистрирует новое устройство; токен показывается один раз.
func (s *Store) Register() (id, token string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	id, token = NewDeviceID(), "dev_"+hex.EncodeToString(b)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.Devices[id] = hashTok(token)
	return id, token, s.save()
}

// Auth проверяет токен устройства.
func (s *Store) Auth(id, token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, ok := s.data.Devices[id]
	return ok && h == hashTok(token)
}

// Exists — зарегистрировано ли устройство.
func (s *Store) Exists(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.data.Devices[id]
	return ok
}

// SetTXT / DelTXT — записи _acme-challenge.
func (s *Store) SetTXT(fqdn, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	fqdn = strings.ToLower(strings.TrimSuffix(fqdn, "."))
	for _, v := range s.data.TXT[fqdn] {
		if v == value {
			return nil
		}
	}
	s.data.TXT[fqdn] = append(s.data.TXT[fqdn], value)
	return s.save()
}

func (s *Store) DelTXT(fqdn, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	fqdn = strings.ToLower(strings.TrimSuffix(fqdn, "."))
	var keep []string
	for _, v := range s.data.TXT[fqdn] {
		if v != value {
			keep = append(keep, v)
		}
	}
	if len(keep) == 0 {
		delete(s.data.TXT, fqdn)
	} else {
		s.data.TXT[fqdn] = keep
	}
	return s.save()
}

// TXT — значения записи.
func (s *Store) TXT(fqdn string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string{}, s.data.TXT[strings.ToLower(strings.TrimSuffix(fqdn, "."))]...)
}

// AddCheckpoint сохраняет свидетельство; номера должны расти.
func (s *Store) AddCheckpoint(id string, cp WitnessedCheckpoint) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	l := s.data.Checkpoints[id]
	if n := len(l); n > 0 && cp.Seq <= l[n-1].Seq {
		if cp.Seq == l[n-1].Seq && cp.Head == l[n-1].Head {
			return nil
		}
		return errors.New("checkpoint sequence must increase (possible log rewrite)")
	}
	s.data.Checkpoints[id] = append(l, cp)
	return s.save()
}

// Checkpoints — свидетельства устройства.
func (s *Store) Checkpoints(id string) []WitnessedCheckpoint {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]WitnessedCheckpoint{}, s.data.Checkpoints[id]...)
}
