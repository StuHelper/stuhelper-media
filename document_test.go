package media_test

import (
	"archive/zip"
	"bytes"
	"errors"
	media "github.com/StuHelper/stuhelper-media"
	"testing"
)

func TestDocumentTypeValidation(t *testing.T) {
	h := newFixture(t)
	cfg := h.cfg
	profile := cfg.Profiles["documents"]
	cases := map[string][]byte{"text/markdown": []byte("# Lecture\n"), "text/csv": []byte("a,b\n1,2\n"), "application/json": []byte("{\"course\":1}")}
	for ext, part := range map[string]string{"wordprocessingml.document": "word/document.xml", "spreadsheetml.sheet": "xl/workbook.xml", "presentationml.presentation": "ppt/presentation.xml"} {
		var b bytes.Buffer
		z := zip.NewWriter(&b)
		for _, name := range []string{"[Content_Types].xml", part} {
			w, e := z.Create(name)
			must(t, e)
			_, e = w.Write([]byte("<fixture/>"))
			must(t, e)
		}
		must(t, z.Close())
		cases["application/vnd.openxmlformats-officedocument."+ext] = b.Bytes()
	}
	for typ := range cases {
		profile.AllowedTypes = append(profile.AllowedTypes, typ)
	}
	cfg.Profiles["documents"] = profile
	s, e := media.New(h.repo, h.policy, h.store, cfg)
	must(t, e)
	defer s.Close(h.ctx)
	for typ, data := range cases {
		t.Run(typ, func(t *testing.T) {
			r := request(data)
			r.ContentType = typ
			v, e := s.CreateUpload(h.ctx, user, typ, r)
			must(t, e)
			_, e = s.Upload(h.ctx, user, v.UploadID, "bytes", bytes.NewReader(data))
			must(t, e)
			view, e := s.GetVersion(h.ctx, user, v.ID)
			must(t, e)
			if view.State != "awaiting_approval" || view.Healthy < 1 {
				t.Fatal(view.State, view.Healthy)
			}
		})
	}
	profile.AllowedTypes = []string{"application/x-unknown-course-format"}
	cfg.Profiles["documents"] = profile
	if _, e = media.New(h.repo, h.policy, h.store, cfg); !errors.Is(e, media.ErrInput) {
		t.Fatalf("unrecognized profile accepted: %v", e)
	}
}
