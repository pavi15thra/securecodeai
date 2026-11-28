
package com.securecodeai.controller;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.securecodeai.model.ScanRequest;
import com.securecodeai.model.ScanResponse;
import com.securecodeai.service.CodeAnalysisService;

@RestController
@RequestMapping("/api")
public class CodeAnalysisController {

    private final CodeAnalysisService codeAnalysisService;

    public CodeAnalysisController(CodeAnalysisService codeAnalysisService) {
        this.codeAnalysisService = codeAnalysisService;
    }

    @PostMapping("/scan")
    public ScanResponse scanCode(@RequestBody ScanRequest request) {

        String sourceCode = request.getSourceCode();

        return codeAnalysisService.analyzeCode(sourceCode);
    }
}
