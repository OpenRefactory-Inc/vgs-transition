# ******************************************************************************************************* #
#                                                                                                         #
#  OPENREFACTORY CONFIDENTIAL                                                                             #
#  __________________                                                                                     #
#                                                                                                         #
#  Copyright (c) 2025 OpenRefactory, Inc. All Rights Reserved.                                            #
#                                                                                                         #
#  NOTICE: All information contained herein is, and remains the property of OpenRefactory, Inc. The       #
#  intellectual and technical concepts contained herein are proprietary to OpenRefactory, Inc. and        #
#  may be covered by U.S. and Foreign Patents, patents in process, and are protected by trade secret      #
#  or copyright law. Dissemination of this information or reproduction of this material is strictly       #
#  forbidden unless prior written permission is obtained from OpenRefactory, Inc.                         #
#                                                                                                         #
#  Author: Saadman Ahmed (OpenRefactory, Inc.) - Initial implementation                                   #
# ******************************************************************************************************* #
import argparse

from analysis import Analysis

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="""Analyze function callgraphs and root cause functions
        Find out all paths that lead to the root cause"""
    )
    parser.add_argument("--input", required=True, help="Path to input JSON file")
    parser.add_argument("--output", required=True, help="Path to output JSON file")
    args = parser.parse_args()

    analysis = Analysis(input=args.input)
    analysis.run()
    analysis.export_vex(output=args.output)
