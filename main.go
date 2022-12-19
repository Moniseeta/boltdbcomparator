package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"reflect"
	"strings"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/exp/maps"
)

type Details struct {
	Platform      string
	NestedBuckets []PackageDetails
}

type DetailsMap map[string]PackageDetailsMap // key is Platform

type PackageDetails struct {
	Pkg  string
	CVEs []CVE
}

type PackageDetailsMap map[string]interface{}

type CVE struct {
	CVEID   string
	Details interface{}
}

//type CVEMap map[string]interface{}

func main() {

	var db1Path, db2Path string
	fmt.Println("Enter the path of DB1; DB2")
	fmt.Scanf("%s %s", &db1Path, &db2Path)

	if db1Path == "" || db2Path == "" {
		fmt.Println("Enter valid DB paths")
	}
	db1, err := bolt.Open(db1Path, 0666, nil)
	if err != nil {
		log.Fatal(err)
	}
	db2, err := bolt.Open(db2Path, 0666, nil)
	if err != nil {
		log.Fatal(err)
	}
	//defer os.RemoveAll(db1.Path()) // nolint: errcheck
	//defer os.RemoveAll(db2.Path()) // nolint: errcheck
	//var listA, listB []Details
	var mapA, mapB DetailsMap
	var rootBuckets1, rootBuckets2 []string
	err = db1.View(func(tx *bolt.Tx) error {
		err = tx.ForEach(func(bucket []byte, _ *bolt.Bucket) error {
			rootBuckets1 = append(rootBuckets1, string(bucket))
			return nil
		})
		_, mapA, err = getAllValues(tx, rootBuckets1)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		log.Fatal("Unable to get data from DB1", err)
	}
	err = db2.View(func(tx *bolt.Tx) error {
		err = tx.ForEach(func(bucket []byte, _ *bolt.Bucket) error {
			rootBuckets2 = append(rootBuckets2, string(bucket))

			return nil
		})
		if err != nil {
			return err
		}
		_, mapB, err = getAllValues(tx, rootBuckets2)
		if err != nil {
			log.Fatal(err.Error())
		}
		return nil
	})
	extraRootA, extraRootB := diffLists(rootBuckets1, rootBuckets2)
	if len(extraRootA) != 0 && len(extraRootB) != 0 {
		fmt.Println(formatListDiff(rootBuckets1, rootBuckets2, extraRootA, extraRootB))
	}

	//fmt.Println(mapA, mapB)

	compareDetails(mapA, mapB)
	//extraA, extraB := diffLists(reflect.ValueOf(listA).Interface(), reflect.ValueOf(listB).Interface())
	//fmt.Println(formatListDiff(reflect.ValueOf(listA).Interface(), reflect.ValueOf(listB).Interface(), extraA, extraB))

	// Close database to release the file lock.
	if err := db1.Close(); err != nil {
		log.Fatal(err)
	}
	if err := db2.Close(); err != nil {
		log.Fatal(err)
	}
}

func compareDetails(mapA, mapB DetailsMap) {

	finalComparison := make(map[string]PackageDetailsMap)
	for platformA, pkgDetailsListA := range mapA {
		pkgDetailsListB := mapB[platformA]
		//if len(pkgDetailsListA) != len(pkgDetailsListB) {
		//	fmt.Printf("Number of elements not equal in both DB for platform %s : DB 1: %v - DB 2 : %v", platformA, pkgDetailsListA, pkgDetailsListB)
		//	return
		//}
		for key, valA := range pkgDetailsListA {
			//fmt.Println("For Platform " + platformA + " key " + key + ", calling diff")
			if strings.Contains(key, "Red Hat") {
				continue
			}
			if valA == nil {
				fmt.Println("No value in DB1 for " + platformA + " " + key)
				continue
			}
			if pkgDetailsListB[key] == nil {
				fmt.Println("No value in DB2 for " + platformA + " " + key + " But value in DB1 is " + valA.(string))
				continue
			}
			//extraA, extraB := diffLists(valA, pkgDetailsListB[key])
			if valA != pkgDetailsListB[key] || !reflect.DeepEqual(valA, pkgDetailsListB[key]) {

				finalComparison[key] = make(PackageDetailsMap)
				finalComparison[key]["DB1"] = valA.(string)
				finalComparison[key]["DB2"] = pkgDetailsListB[key].(string)
				//fmt.Println("Differences found for Platform " + platformA + " key " + key)
				//fmt.Printf("Value in DB1 %s ; Value in DB2 %s \n", valA.(string), pkgDetailsListB[key].(string))
			}
		}

	}
	file, _ := json.MarshalIndent(finalComparison, "", " ")

	_ = os.WriteFile("comparedResult.json", file, 0644)
}

func getAllValues(tx *bolt.Tx, baseBucketNames []string) (details []Details, detailMap DetailsMap, err error) {
	detailMap = make(DetailsMap)
	for _, root := range baseBucketNames {
		parentBucket := tx.Bucket([]byte(root))
		if parentBucket == nil {
			continue
		}
		detail, pkgDetMapList, err := getNestedBuckets(parentBucket, root)
		if err == nil {
			detail.Platform = root
			details = append(details, detail)
			detailMap[root] = pkgDetMapList
		}
	}
	return details, detailMap, err
}

func getNestedBuckets(parentBucket *bolt.Bucket, bucketName string) (det Details, pkgDetMapList PackageDetailsMap, err error) {
	//parentBucket := tx.Bucket([]byte(bucketName))
	//if parentBucket == nil {
	//	return det, nil
	//}
	var pkgDetail PackageDetails
	pkgDetailMap := make(PackageDetailsMap)
	err = parentBucket.ForEach(func(key, value []byte) error {
		if value == nil {
			nestedPlatform := bucketName + "%%" + string(key)
			childBucket := parentBucket.Bucket(key)
			childDet, childDetMap, _ := getNestedBuckets(childBucket, nestedPlatform)

			det.NestedBuckets = append(det.NestedBuckets, childDet.NestedBuckets...)
			maps.Copy(pkgDetailMap, childDetMap)
			//pkgDetailMap = childDetMap
			//det.CVEID = childDet.CVEID
			//det.Details = childDet.Details
		} else {
			nestedPlatform := bucketName + "%%" + string(key)
			//cveMap := make(CVEMap)
			pkgDetail.Pkg = bucketName
			pkgDetail.CVEs = append(pkgDetail.CVEs, CVE{
				CVEID:   string(key),
				Details: string(value),
			})
			//cveMap[string(key)] = value
			pkgDetailMap[nestedPlatform] = string(value)
			//det.NestedBuckets = []string{bucketName}
			//
			//det.Details = value
			//det.CVEID = string(key)
		}
		return nil
	})
	if err != nil {
		return det, nil, err
	}
	det.NestedBuckets = append(det.NestedBuckets, pkgDetail)
	//pkgDetailMap = pkgDetailMap
	return det, pkgDetailMap, nil
}

// diffLists diffs two arrays/slices and returns slices of elements that are only in A and only in B.
// If some element is present multiple times, each instance is counted separately (e.g. if something is 2x in A and
// 5x in B, it will be 0x in extraA and 3x in extraB). The order of items in both lists is ignored.
func diffLists(listA, listB interface{}) (extraA, extraB []interface{}) {
	aValue := reflect.ValueOf(listA)
	bValue := reflect.ValueOf(listB)

	aLen := aValue.Len()
	bLen := bValue.Len()

	// Mark indexes in bValue that we already used
	visited := make([]bool, bLen)
	for i := 0; i < aLen; i++ {
		element := aValue.Index(i).Interface()
		found := false
		for j := 0; j < bLen; j++ {
			if visited[j] {
				continue
			}
			if ObjectsAreEqual(bValue.Index(j).Interface(), element) {
				visited[j] = true
				found = true
				break
			}
		}
		if !found {
			extraA = append(extraA, element)
		}
	}

	for j := 0; j < bLen; j++ {
		if visited[j] {
			continue
		}
		extraB = append(extraB, bValue.Index(j).Interface())
	}

	return
}

func ObjectsAreEqual(expected, actual interface{}) bool {
	if expected == nil || actual == nil {
		return expected == actual
	}

	exp, ok := expected.([]byte)
	if !ok {
		return reflect.DeepEqual(expected, actual)
	}

	act, ok := actual.([]byte)
	if !ok {
		return false
	}
	if exp == nil || act == nil {
		return exp == nil && act == nil
	}
	return bytes.Equal(exp, act)
}

func formatListDiff(listA, listB interface{}, extraA, extraB []interface{}) string {
	var msg bytes.Buffer

	msg.WriteString("elements differ")
	if len(extraA) > 0 {
		msg.WriteString("\n\nextra elements in list A:\n")
		for _, val := range extraA {
			msg.WriteString(val.(string))
		}
		//msg.WriteString(spewConfig.Sdump(extraA))
	}
	if len(extraB) > 0 {
		msg.WriteString("\n\nextra elements in list B:\n")
		for _, val := range extraB {
			msg.WriteString(val.(string))
		}
		//msg.WriteString(spewConfig.Sdump(extraB))
	}
	//msg.WriteString("\n\nlistA:\n")
	//msg.WriteString(spewConfig.Sdump(listA))
	//msg.WriteString("\n\nlistB:\n")
	//msg.WriteString(spewConfig.Sdump(listB))

	return msg.String()
}
