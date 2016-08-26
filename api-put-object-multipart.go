/*
 * Minio Go Library for Amazon S3 Compatible Cloud Storage (C) 2015, 2016 Minio, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package minio

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
)

// partUploadRes - the response of a part upload.
type partUploadRes struct {
	size int64 // Send back size to update the progess bar.
	err  error // Send back any error to exit when appropriate.
}

// Comprehensive put object operation involving multipart resumable uploads.
//
// Following code handles these types of readers.
//
//  - *os.File
//  - *minio.Object
//  - Any reader which has a method 'ReadAt()'
//
// If we exhaust all the known types, code proceeds to use stream as
// is where each part is re-downloaded, checksummed and verified
// before upload.
func (c Client) putObjectMultipart(bucketName, objectName string, reader io.Reader, size int64, contentType string, progress io.Reader) (n int64, err error) {
	if size > 0 && size > minPartSize {
		// Verify if reader is *os.File, then use file system functionalities.
		if isFile(reader) {
			return c.putObjectMultipartFromFile(bucketName, objectName, reader.(*os.File), size, contentType, progress)
		}
		// Verify if reader is *minio.Object or io.ReaderAt.
		// NOTE: Verification of object is kept for a specific purpose
		// while it is going to be duck typed similar to io.ReaderAt.
		// It is to indicate that *minio.Object implements io.ReaderAt.
		// and such a functionality is used in the subsequent code
		// path.
		if isObject(reader) || isReadAt(reader) {
			return c.putObjectMultipartFromReadAt(bucketName, objectName, reader.(io.ReaderAt), size, contentType, progress)
		}
	}
	// For any other data size and reader type we do generic multipart
	// approach by staging data in temporary files and uploading them.
	return c.putObjectMultipartStream(bucketName, objectName, reader, size, contentType, progress)
}

// putObjectStream uploads files bigger than 5MiB, and also supports
// special case where size is unknown i.e '-1'.
func (c Client) putObjectMultipartStream(bucketName, objectName string, reader io.Reader, size int64, contentType string, progress io.Reader) (n int64, err error) {
	// Input validation.
	if err := isValidBucketName(bucketName); err != nil {
		return 0, err
	}
	if err := isValidObjectName(objectName); err != nil {
		return 0, err
	}

	// Total data read and written to server. should be equal to 'size' at the end of the call.
	var totalUploadedSize int64

	// Complete multipart upload.
	var complMultipartUpload completeMultipartUpload

	// A map of all previously uploaded parts.
	var partsInfo = make(map[int]objectPart)

	// getUploadID for an object, initiates a new multipart request
	// if it cannot find any previously partially uploaded object.
	uploadID, isNew, err := c.getUploadID(bucketName, objectName, contentType)
	if err != nil {
		return 0, err
	}

	// If This session is a continuation of a previous session fetch all
	// previously uploaded parts info.
	if !isNew {
		// Fetch previously uploaded parts and maximum part size.
		partsInfo, err = c.listObjectParts(bucketName, objectName, uploadID)
		if err != nil {
			return 0, err
		}
	}

	// Calculate the optimal parts info for a given size.
	totalPartsCount, partSize, _, err := optimalPartInfo(size)
	if err != nil {
		return 0, err
	}

	// Create a channel for the go-routines to communicate through.
	partResCh := make(chan partUploadRes, 1)

	fmt.Println("there are ", totalPartsCount, " parts")
	// Loop through parts and upload them in parallel.
	for partNumber := 1; partNumber <= totalPartsCount; partNumber++ {
		go func(partNum int) {
			fmt.Println("starting routine, ", partNum)
			tmpBuffer := new(bytes.Buffer)

			// Choose hash algorithms to be calculated by hashCopyN, avoid sha256
			// with non-v4 signature request or HTTPS connection
			hashSums := make(map[string][]byte)
			hashAlgos := make(map[string]hash.Hash)
			hashAlgos["md5"] = md5.New()
			if c.signature.isV4() && !c.secure {
				hashAlgos["sha256"] = sha256.New()
			}

			// Calculates hash sums while copying partSize bytes into tmpBuffer.
			prtSize, rErr := hashCopyN(hashAlgos, hashSums, tmpBuffer, reader, partSize)
			if rErr != nil {
				if rErr != io.EOF {
					// Send the error through the channel and exit
					// the goroutine.
					partResCh <- partUploadRes{
						size: 0,
						err:  err,
					}
					return
				}
			}

			// TODO: figure out what to do about concurrent access to the progress bar.
			// MAYBE: handle it when each part comes through the response channel.
			// Update progress reader appropriately to the latest offset
			// as we read from the source.
			// reader = newHook(tmpBuffer, progress)

			// Verify if part should be uploaded.
			if shouldUploadPart(objectPart{
				ETag:       hex.EncodeToString(hashSums["md5"]),
				PartNumber: partNum,
				Size:       prtSize,
			}, partsInfo) {
				// Proceed to upload the part.
				var objPart objectPart
				objPart, err = c.uploadPart(bucketName, objectName, uploadID, tmpBuffer, partNum, hashSums["md5"], hashSums["sha256"], prtSize)
				if err != nil {
					partResCh <- partUploadRes{
						size: 0,
						err:  err,
					}
					// Exit the goroutine.
					return
				}
				// Save successfully uploaded part metadata.
				partsInfo[partNum] = objPart
			} else {
				// This part was not uploaded. Send back no error and just the size
				// to update the progress bar on the other end.
				partResCh <- partUploadRes{
					size: prtSize,
					err:  nil,
				}
				// Exit the goroutine.
				return
			}

			// Done with uploading: Reached EOF and do not
			// know the expected size so exit.
			if size < 0 && rErr == io.EOF {
				partResCh <- partUploadRes{
					size: size,
					err:  rErr,
				}
				// Leave the goroutine.
				// Handle this err specially by
				// exiting the select block below and
				// continuing on without the rest of the
				// goroutines.
				return
			}
			fmt.Println("Leaving routine ", partNum)
			fmt.Println("feeding partResCh success")
			// Part was successfully uploaded.
			// Send back the size to update progress bar.
			partResCh <- partUploadRes{
				size: prtSize,
				err:  nil,
			}
		}(partNumber)
	}

	// Keep track of how much of the object has been uploaded.
	var totalUploadSize int64
	count := totalPartsCount
loop:
	for count > 0 {
		fmt.Println(count)
		select {
		case partRes := <-partResCh:
			fmt.Println("drew from partResCh")
			// Need to verify if the error was because we reached
			// EOF and do not know the size of the file.
			if partRes.err != nil {
				if err == io.EOF && partRes.size < 0 {
					// Here need to only exit the for/select block and continue.
					break loop
				}
				return totalUploadSize, err
			}
			// Update the totalUploadSize.
			totalUploadSize += partRes.size
			// Update the progress bar.
			if _, err := io.CopyN(ioutil.Discard, progress, partRes.size); err != nil {
				return totalUploadSize, err
			}
			count--
		}
	}

	// Verify if we uploaded all the data.
	if size > 0 {
		if totalUploadedSize != size {
			return totalUploadedSize, ErrUnexpectedEOF(totalUploadedSize, size, bucketName, objectName)
		}
	}

	// Loop over uploaded parts to save them in a Parts array before completing the multipart request.
	for _, part := range partsInfo {
		var complPart completePart
		complPart.ETag = part.ETag
		complPart.PartNumber = part.PartNumber
		complMultipartUpload.Parts = append(complMultipartUpload.Parts, complPart)
	}

	if size > 0 {
		// Verify if totalPartsCount is not equal to total list of parts.
		if totalPartsCount != len(complMultipartUpload.Parts) {
			return totalUploadedSize, ErrInvalidParts(totalPartsCount, len(complMultipartUpload.Parts))
		}
	}

	// Sort all completed parts.
	sort.Sort(completedParts(complMultipartUpload.Parts))
	_, err = c.completeMultipartUpload(bucketName, objectName, uploadID, complMultipartUpload)
	if err != nil {
		return totalUploadedSize, err
	}

	// Return final size.
	return totalUploadedSize, nil
}

// initiateMultipartUpload - Initiates a multipart upload and returns an upload ID.
func (c Client) initiateMultipartUpload(bucketName, objectName, contentType string) (initiateMultipartUploadResult, error) {
	// Input validation.
	if err := isValidBucketName(bucketName); err != nil {
		return initiateMultipartUploadResult{}, err
	}
	if err := isValidObjectName(objectName); err != nil {
		return initiateMultipartUploadResult{}, err
	}

	// Initialize url queries.
	urlValues := make(url.Values)
	urlValues.Set("uploads", "")

	if contentType == "" {
		contentType = "application/octet-stream"
	}

	// Set ContentType header.
	customHeader := make(http.Header)
	customHeader.Set("Content-Type", contentType)

	reqMetadata := requestMetadata{
		bucketName:   bucketName,
		objectName:   objectName,
		queryValues:  urlValues,
		customHeader: customHeader,
	}

	// Execute POST on an objectName to initiate multipart upload.
	resp, err := c.executeMethod("POST", reqMetadata)
	defer closeResponse(resp)
	if err != nil {
		return initiateMultipartUploadResult{}, err
	}
	if resp != nil {
		if resp.StatusCode != http.StatusOK {
			return initiateMultipartUploadResult{}, httpRespToErrorResponse(resp, bucketName, objectName)
		}
	}
	// Decode xml for new multipart upload.
	initiateMultipartUploadResult := initiateMultipartUploadResult{}
	err = xmlDecoder(resp.Body, &initiateMultipartUploadResult)
	if err != nil {
		return initiateMultipartUploadResult, err
	}
	return initiateMultipartUploadResult, nil
}

// uploadPart - Uploads a part in a multipart upload.
func (c Client) uploadPart(bucketName, objectName, uploadID string, reader io.Reader, partNumber int, md5Sum, sha256Sum []byte, size int64) (objectPart, error) {
	// Input validation.
	if err := isValidBucketName(bucketName); err != nil {
		return objectPart{}, err
	}
	if err := isValidObjectName(objectName); err != nil {
		return objectPart{}, err
	}
	if size > maxPartSize {
		return objectPart{}, ErrEntityTooLarge(size, maxPartSize, bucketName, objectName)
	}
	if size <= -1 {
		return objectPart{}, ErrEntityTooSmall(size, bucketName, objectName)
	}
	if partNumber <= 0 {
		return objectPart{}, ErrInvalidArgument("Part number cannot be negative or equal to zero.")
	}
	if uploadID == "" {
		return objectPart{}, ErrInvalidArgument("UploadID cannot be empty.")
	}

	// Get resources properly escaped and lined up before using them in http request.
	urlValues := make(url.Values)
	// Set part number.
	urlValues.Set("partNumber", strconv.Itoa(partNumber))
	// Set upload id.
	urlValues.Set("uploadId", uploadID)

	reqMetadata := requestMetadata{
		bucketName:         bucketName,
		objectName:         objectName,
		queryValues:        urlValues,
		contentBody:        reader,
		contentLength:      size,
		contentMD5Bytes:    md5Sum,
		contentSHA256Bytes: sha256Sum,
	}

	// Execute PUT on each part.
	resp, err := c.executeMethod("PUT", reqMetadata)
	defer closeResponse(resp)
	if err != nil {
		return objectPart{}, err
	}
	if resp != nil {
		if resp.StatusCode != http.StatusOK {
			return objectPart{}, httpRespToErrorResponse(resp, bucketName, objectName)
		}
	}
	// Once successfully uploaded, return completed part.
	objPart := objectPart{}
	objPart.Size = size
	objPart.PartNumber = partNumber
	// Trim off the odd double quotes from ETag in the beginning and end.
	objPart.ETag = strings.TrimPrefix(resp.Header.Get("ETag"), "\"")
	objPart.ETag = strings.TrimSuffix(objPart.ETag, "\"")
	return objPart, nil
}

// completeMultipartUpload - Completes a multipart upload by assembling previously uploaded parts.
func (c Client) completeMultipartUpload(bucketName, objectName, uploadID string, complete completeMultipartUpload) (completeMultipartUploadResult, error) {
	// Input validation.
	if err := isValidBucketName(bucketName); err != nil {
		return completeMultipartUploadResult{}, err
	}
	if err := isValidObjectName(objectName); err != nil {
		return completeMultipartUploadResult{}, err
	}

	// Initialize url queries.
	urlValues := make(url.Values)
	urlValues.Set("uploadId", uploadID)

	// Marshal complete multipart body.
	completeMultipartUploadBytes, err := xml.Marshal(complete)
	if err != nil {
		return completeMultipartUploadResult{}, err
	}

	// Instantiate all the complete multipart buffer.
	completeMultipartUploadBuffer := bytes.NewReader(completeMultipartUploadBytes)
	reqMetadata := requestMetadata{
		bucketName:         bucketName,
		objectName:         objectName,
		queryValues:        urlValues,
		contentBody:        completeMultipartUploadBuffer,
		contentLength:      int64(len(completeMultipartUploadBytes)),
		contentSHA256Bytes: sum256(completeMultipartUploadBytes),
	}

	// Execute POST to complete multipart upload for an objectName.
	resp, err := c.executeMethod("POST", reqMetadata)
	defer closeResponse(resp)
	if err != nil {
		return completeMultipartUploadResult{}, err
	}
	if resp != nil {
		if resp.StatusCode != http.StatusOK {
			return completeMultipartUploadResult{}, httpRespToErrorResponse(resp, bucketName, objectName)
		}
	}

	// Read resp.Body into a []bytes to parse for Error response inside the body
	var b []byte
	b, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return completeMultipartUploadResult{}, err
	}
	// Decode completed multipart upload response on success.
	completeMultipartUploadResult := completeMultipartUploadResult{}
	err = xmlDecoder(bytes.NewReader(b), &completeMultipartUploadResult)
	if err != nil {
		// xml parsing failure due to presence an ill-formed xml fragment
		return completeMultipartUploadResult, err
	} else if completeMultipartUploadResult.Bucket == "" {
		// xml's Decode method ignores well-formed xml that don't apply to the type of value supplied.
		// In this case, it would leave completeMultipartUploadResult with the corresponding zero-values
		// of the members.

		// Decode completed multipart upload response on failure
		completeMultipartUploadErr := ErrorResponse{}
		err = xmlDecoder(bytes.NewReader(b), &completeMultipartUploadErr)
		if err != nil {
			// xml parsing failure due to presence an ill-formed xml fragment
			return completeMultipartUploadResult, err
		}
		return completeMultipartUploadResult, completeMultipartUploadErr
	}
	return completeMultipartUploadResult, nil
}
