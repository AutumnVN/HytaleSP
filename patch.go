package main

import (
	"fmt"

	"github.com/itchio/headway/state"
	"github.com/itchio/lake/pools/fspool"
	"github.com/itchio/savior/filesource"
	"github.com/itchio/wharf/pwr/bowl"
	"github.com/itchio/wharf/pwr/patcher"

	_ "github.com/itchio/wharf/decompressors/cbrotli"
)


func applyPatch(source string, destination string, patchFilename string) {

	consumer := &state.Consumer {
		OnProgress: func(progress float64) {
			fmt.Printf("Progress: %d\n", int(progress));
		},
		OnProgressLabel: func(progress string) {
			fmt.Printf("Progress: %s\n", progress);
		},
	}


	patchReader, _ := filesource.Open(patchFilename);
	p, _ := patcher.New(patchReader, consumer);

	targetPool := fspool.New(p.GetTargetContainer(), source);

	b, _ := bowl.NewFreshBowl(bowl.FreshBowlParams{
		SourceContainer: p.GetSourceContainer(),
		TargetContainer: p.GetTargetContainer(),
		TargetPool: targetPool,
		OutputFolder: destination,
	});

	// start the patch
	p.Resume(nil, targetPool, b);

}
