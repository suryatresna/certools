/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// certCmd represents the cert command
var certCmd = &cobra.Command{
	Use:   "certificate",
	Short: "Generate a new certificate",
	Long: `
	Generate a new certificate using the provided private key
	`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("cert called")
	},
}

func init() {
	rootCmd.AddCommand(certCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// certCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// certCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
