package main

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/exp/maps"
	"golang.org/x/xerrors"
)

func main() {
	db, err := bolt.Open("/home/moni/test_files/trivy/prod_2Feb2023/trivy.db", 066, nil)
	if err != nil {
		log.Fatal(err)
	}

	finalMap := map[string]map[string]map[string]int{}
	osFinalMap := map[string]map[string]int{}
	err = db.View(func(tx *bolt.Tx) error {
		rootBucket := tx.Bucket([]byte("CPE"))
		if rootBucket == nil {
			return nil
		}
		err = rootBucket.ForEach(func(pkg, v []byte) error {
			packageBucket := rootBucket.Bucket(pkg)
			if packageBucket == nil {
				return nil
			}
			osMap := map[string]map[string]int{}
			err = packageBucket.ForEach(func(cve, v []byte) error {
				detail := map[string]interface{}{}
				if err := json.Unmarshal(v, &detail); err != nil {
					return xerrors.Errorf("failed to unmarshall CVE_detail: %w", err)
				}
				if details, ok := detail["Custom"]; ok {
					if detailsMap, ok := details.(map[string]interface{}); ok {
						for k := range detailsMap {
							osArr := strings.Split(k, ":")
							if _, ok := osMap[osArr[0]]; !ok {
								osMap[osArr[0]] = map[string]int{
									osArr[1]: 1,
								}
							} else {
								osMap[osArr[0]][osArr[1]] = 1
							}
							if _, ok := osFinalMap[osArr[0]]; !ok {
								osFinalMap[osArr[0]] = map[string]int{
									osArr[1]: 1,
								}
							} else {
								osFinalMap[osArr[0]][osArr[1]] = 1
							}

							// osMap[osArr[0]] = append(osMap[osArr[0]], osArr[1])

						}
					}
				}
				return nil
			})
			if len(osMap) != 0 {
				finalMap[string(pkg)] = osMap
			}
			return nil
		})
		return nil
	})
	if err != nil {
		log.Fatal("Unable to get data from DB1", err)
	}
	for k, v := range finalMap {
		var finalString, osName, ostypes string
		pkg := k
		// fmt.Println("package " + k)
		for os, val := range v {
			osName = os
			// fmt.Println("OS " + os)
			ostypes = strings.Join(maps.Keys(val), "&")
			finalString = strings.Join([]string{pkg, osName, ostypes}, "|")
			fmt.Println(finalString)
		}

	}

	fmt.Println("OS LIST")
	for os, val := range osFinalMap {
		osName := os

		ostypes := strings.Join(maps.Keys(val), "&")
		finalString := strings.Join([]string{osName, ostypes}, "|")
		fmt.Println(finalString)
	}
}
