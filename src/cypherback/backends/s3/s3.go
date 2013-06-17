package s3

import (
	"launchpad.net/goamz/s3"
	"launchpad.net/goamz/aws"
)

type S3 struct {
	bucket *s3.Bucket
}

func (s *S3) WriteSecrets(id string, encSecrets []byte) (err error) {
	path := id + "/secrets"
	err = s.bucket.Put(path, encSecrets, "application/vnd.cypherback.secrets", "")
	if err != nil {
		return err
	}
	// create a defaultSecrets if it does not exist
	resp, err := s.bucket.List("defaultSecrets", "/", "", 1)
	if err != nil {
		return err
	}
	if len(resp.Contents) == 0 {
		err = s.bucket.Put("defaultSecrets", []byte(id), "application/vnd.cypherback.secretsid", "")
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *S3) ReadSecrets() (encSecrets []byte, err error) {
	id, err := s.bucket.Get("defaultSecrets")
	if err != nil {
		return nil, err
	}
	return s.bucket.Get(string(id) + "/secrets")
}

func (s *S3) WriteBackupSet(secretsId, id string, data []byte) error {
	path := secretsId + "/sets/" + id
	return s.bucket.Put(path, data, "application/vnd.cypherback.backupset", "")
}

func (s *S3) ReadBackupSet(secretsId, id string) (data []byte, err error) { 
	return s.bucket.Get(secretsId + "/sets/" + id)
}

func chunkIdToPath(secretsId, id string) string {
	return secretsId + "/chunks/" + id[0:2] + "/" + id[2:4] + "/" + id[4:6] + "/" + id[6:8] + "/" + id
}

func (s *S3) WriteChunk(secretsId, id string, data []byte) error {
	return s.bucket.Put(chunkIdToPath(secretsId, id), data, "application/vnd.cypherback.chunk", "")
}

func (s *S3) ReadChunk(secretsId, id string) (date []byte, err error) {
	return s.bucket.Get(chunkIdToPath(secretsId, id))
}

func New(access, secret, endpoint, bucketName string) (s3Backend *S3, err error) {
	s3Conn := s3.New(aws.Auth{access, secret}, aws.Region{S3Endpoint: endpoint})
	bucket := s3Conn.Bucket(bucketName)
	err = bucket.PutBucket("")
	if err != nil {
		return nil, err
	}
	return &S3{bucket}, nil
}