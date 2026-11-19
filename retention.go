package media

import "context"

// SourceRetention checks the owning module's durable retention decision before
// media reclaims an otherwise unused source. It grants no read or download rights.
type SourceRetention func(context.Context, string, string) (bool, error)

func (s *Service) retainSource(ctx context.Context, v Version) (bool, error) {
	if s.cfg.SourceRetention == nil {
		return false, nil
	}
	return s.cfg.SourceRetention(ctx, v.Profile.Module, v.ID)
}

// PublicationReferenceID identifies one publishing operation even when its
// result was lost. A later publication of the same version gets a separate ID.
func PublicationReferenceID(versionID string, b Binding, operationID string) string {
	return hash([]string{"publication", versionID, b.Module, b.ResourceID, operationID})
}

func (s *Service) requireReclaimable(ctx context.Context, v Version) error {
	keep, err := s.retainSource(ctx, v)
	if err != nil {
		return err
	}
	if keep {
		return ErrConflict
	}
	return nil
}
