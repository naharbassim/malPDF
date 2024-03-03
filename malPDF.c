/*
***************************************************************************
**                                                                       **
**    Description:                                                       **
**      This tool enables you to identify the types of objects contained **
**      within a PDF file, allowing you to assess whether it is          **
**      malicious. Additionally, it can extract JavaScript for further   **
**      analysis.                                                        **
**                                                                       **
**                                                                       **  
**    Author:                                                            **
**      Nahar                                                            **
**                                                                       **
***************************************************************************
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int CountKeyword(const char* filePath, const char* word) {
    FILE *file = fopen(filePath, "rb");
    if (!file) {
        printf("Could not open file %s\n", filePath);
        return -1;
    }

    int count = 0;
    char buffer[1024];
    size_t wordLength = strlen(word);

    while (fread(buffer, 1, sizeof(buffer), file) > 0) {
        for (int i = 0; i < sizeof(buffer) - wordLength; ++i) {
            if (strncmp(&buffer[i], word, wordLength) == 0) {
                count++;
                i += wordLength - 1; 
            }
        }
    }

    fclose(file);
    return count;
}

void ExtractJS(const char* inputFilePath) {
    const char* outputFilePath = "JSoutput.txt";

    FILE *file = fopen(inputFilePath, "rb");
    if (!file) {
        printf("Could not open file %s\n", inputFilePath);
        return;
    }

    FILE *outputFile = fopen(outputFilePath, "w");
    if (!outputFile) {
        printf("Could not open file %s for writing\n", outputFilePath);
        fclose(file); 
        return;
    }

    char buffer[5048];
    size_t bytesRead;
    const char* word = "/S/JavaScript";
    size_t wordLength = strlen(word);

    while ((bytesRead = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        for (size_t i = 0; i < bytesRead - wordLength; ++i) {
            if (strncmp(&buffer[i], word, wordLength) == 0) {
                size_t start, end;
                for (start = i; start > 0 && buffer[start] != '<'; --start);
                for (end = i; end < bytesRead && buffer[end] != '>'; ++end);

                if (buffer[start] == '<' && buffer[end] == '>') {
                    fprintf(outputFile, "<<");
                    for (size_t j = start + 1; j < end; ++j) {
                        fprintf(outputFile, "%c", buffer[j]);
                    }
                    fprintf(outputFile, ">>\n\n"); 
                }
                i += wordLength - 1;
            }
        }
    }
    printf("Javascript Objects has been extracted successfully !\n");
    fclose(file);
    fclose(outputFile);
}

void ExtractLaunch(const char* inputFilePath) {
    const char* outputFilePath = "LaunchOutput.txt";

    FILE *file = fopen(inputFilePath, "rb");
    if (!file) {
        printf("Could not open file %s\n", inputFilePath);
        return;
    }

    FILE *outputFile = fopen(outputFilePath, "w");
    if (!outputFile) {
        printf("Could not open file %s for writing\n", outputFilePath);
        fclose(file); 
        return;
    }

    char buffer[5048];
    size_t bytesRead;
    const char* word = "/S/Launch";
    size_t wordLength = strlen(word);

    while ((bytesRead = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        for (size_t i = 0; i < bytesRead - wordLength; ++i) {
            if (strncmp(&buffer[i], word, wordLength) == 0) {
                size_t start, end;
                for (start = i; start > 0 && buffer[start] != '<'; --start);
                for (end = i; end < bytesRead && buffer[end] != '>'; ++end);

                if (buffer[start] == '<' && buffer[end] == '>') {
                    fprintf(outputFile, "<<");
                    for (size_t j = start + 1; j < end; ++j) {
                        fprintf(outputFile, "%c", buffer[j]);
                    }
                    fprintf(outputFile, ">>\n\n"); 
                }
                i += wordLength - 1;
            }
        }
    }
    printf("Launch Objects has been extracted successfully !\n");
    fclose(file);
    fclose(outputFile);
}


int main(int argc, char *argv[]) {
    
    
    if(argc < 2){printf("You need to pass PDF path.");return -1;};

    char* filePath = argv[1];
    
    FILE *file = fopen(filePath, "rb");
    if (!file) {printf("Could not open file '%s'\n", filePath);return -1;}


    char *keywords[] = {"obj","stream","xref","trailer","startxref","Page","Encrypt","ObjStm","JS","JavaScript","AA","OpenAction","AcroForm","JBIG2Decode","RichMedia","Launch","EmbeddedFile","XFA",};


    printf("====================================================\n");
    for(int i=0; i < sizeof(keywords)/sizeof(keywords[0]); i++){
        int count = CountKeyword(filePath, keywords[i]);
        printf("%d -> %s \n",count,keywords[i]);
    }
    printf("====================================================\n");
    ExtractJS(filePath);
    printf("====================================================\n");
    ExtractLaunch(filePath);
    printf("====================================================\n");

    return 0;

}