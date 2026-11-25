package com.phishguard.service;

import com.lowagie.text.Document;
import com.lowagie.text.DocumentException;
import com.lowagie.text.PageSize;
import com.lowagie.text.Paragraph;
import com.lowagie.text.Phrase;
import com.lowagie.text.pdf.PdfPCell;
import com.lowagie.text.pdf.PdfPTable;
import com.lowagie.text.pdf.PdfWriter;
import com.phishguard.ml.UrlPredictionResult;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;

@Service
public class ReportService {

    public String toCsv(UrlPredictionResult result) {
        String indicators = String.join("; ", result.suspiciousIndicators()).replace("\"", "\"\"");
        return "prediction,risk_category,risk_score,model_version,indicators\n\"" +
            result.predictedClass() + "\",\"" +
            result.riskCategory() + "\"," + result.riskScore() + ",\"" +
            result.modelVersion() + "\",\"" + indicators + "\"";
    }

    public byte[] toPdf(UrlPredictionResult result) throws DocumentException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        Document document = new Document(PageSize.A4);
        PdfWriter.getInstance(document, output);
        document.open();

        document.add(new Paragraph("PhishGuard AI URL Threat Report"));
        document.add(new Paragraph("Prediction: " + result.predictedClass()));
        document.add(new Paragraph("Risk category: " + result.riskCategory()));
        document.add(new Paragraph("Risk score: " + result.riskScore() + "/100"));
        document.add(new Paragraph("Model version: " + result.modelVersion()));
        document.add(new Paragraph("Timestamp: " + result.predictionTimestamp()));

        PdfPTable table = new PdfPTable(1);
        table.addCell(new PdfPCell(new Phrase("Suspicious indicators")));
        if (result.suspiciousIndicators().isEmpty()) {
            table.addCell("No strong deterministic indicators detected.");
        } else {
            for (String indicator : result.suspiciousIndicators()) {
                table.addCell(indicator);
            }
        }
        document.add(table);
        document.add(new Paragraph("Explanation: " + result.explanation()));
        document.close();
        return output.toByteArray();
    }
}
