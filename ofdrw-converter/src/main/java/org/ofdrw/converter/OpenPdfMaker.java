package org.ofdrw.converter;


import com.lowagie.text.Document;
import java.awt.Color;
import com.lowagie.text.DocumentException;
import com.lowagie.text.Image;
import com.lowagie.text.Rectangle;
import com.lowagie.text.pdf.BaseFont;
import com.lowagie.text.pdf.PdfContentByte;
import com.lowagie.text.pdf.PdfFileSpecification;
import com.lowagie.text.pdf.PdfGState;
import com.lowagie.text.pdf.PdfName;
import com.lowagie.text.pdf.PdfShading;
import com.lowagie.text.pdf.PdfShadingPattern;
import com.lowagie.text.pdf.PdfWriter;
import org.apache.fontbox.ttf.OTFParser;
import org.apache.fontbox.ttf.TTFParser;
import org.apache.fontbox.ttf.TrueTypeCollection;
import org.apache.fontbox.ttf.TrueTypeFont;
import org.dom4j.Element;
import org.ofdrw.converter.point.PathPoint;
import org.ofdrw.converter.point.TextCodePoint;
import org.ofdrw.converter.utils.CommonUtil;
import org.ofdrw.converter.utils.PointUtil;
import org.ofdrw.core.annotation.pageannot.Annot;
import org.ofdrw.core.attachment.CT_Attachment;
import org.ofdrw.core.basicStructure.pageObj.layer.CT_Layer;
import org.ofdrw.core.basicStructure.pageObj.layer.PageBlockType;
import org.ofdrw.core.basicStructure.pageObj.layer.block.*;
import org.ofdrw.core.basicStructure.res.CT_MultiMedia;
import org.ofdrw.core.basicType.ST_Array;
import org.ofdrw.core.basicType.ST_Box;
import org.ofdrw.core.basicType.ST_Pos;
import org.ofdrw.core.basicType.ST_RefID;
import org.ofdrw.core.compositeObj.CT_VectorG;
import org.ofdrw.core.graph.pathObj.CT_Path;
import org.ofdrw.core.graph.pathObj.FillColor;
import org.ofdrw.core.graph.pathObj.Rule;
import org.ofdrw.core.graph.pathObj.StrokeColor;
import org.ofdrw.core.pageDescription.CT_GraphicUnit;
import org.ofdrw.core.pageDescription.clips.Area;
import org.ofdrw.core.pageDescription.clips.CT_Clip;
import org.ofdrw.core.pageDescription.color.color.CT_AxialShd;
import org.ofdrw.core.pageDescription.color.color.CT_Color;
import org.ofdrw.core.pageDescription.color.color.CT_RadialShd;
import org.ofdrw.core.pageDescription.color.color.ColorClusterType;
import org.ofdrw.core.pageDescription.drawParam.CT_DrawParam;
import org.ofdrw.core.signatures.appearance.StampAnnot;
import org.ofdrw.core.text.font.CT_Font;
import org.ofdrw.reader.OFDReader;
import org.ofdrw.reader.PageInfo;
import org.ofdrw.reader.ResourceLocator;
import org.ofdrw.reader.ResourceManage;
import org.ofdrw.reader.model.AnnotionEntity;
import org.ofdrw.reader.model.StampAnnotEntity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.imageio.ImageIO;
import java.awt.geom.AffineTransform;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import static org.ofdrw.converter.utils.CommonUtil.convertPDColor;
import static org.ofdrw.converter.utils.CommonUtil.converterDpi;
import static org.ofdrw.core.text.text.Direction.Angle_90;
import static org.ofdrw.core.text.text.Direction.Angle_180;
import static org.ofdrw.core.text.text.Direction.Angle_270;


/**
 * OpenPDF实现的PDF转换器
 * <p>
 * 取代原 {@code PdfboxMaker}，避免 PDFBox 启动时 {@code java.awt.image.ColorModel} 的
 * {@code <clinit>} 在 native-image 构建阶段触发 {@code UnsatisfiedLinkError}。
 * OpenPDF 是 LGPL 协议，无 AWT 运行时依赖，体积小、native-image 友好。
 */
public class OpenPdfMaker {

    private static final Logger logger = LoggerFactory.getLogger(OpenPdfMaker.class);

    /**
     * OFD解析器
     */
    private final OFDReader reader;

    /**
     * PDF文档上下文
     */
    private final Document pdf;

    /**
     * PDF写入器
     */
    private final PdfWriter pdfWriter;

    /**
     * 资源加载器
     */
    private final ResourceManage resMgt;

    /**
     * 字体缓存防止重复加载字体
     */
    private final Map<String, BaseFont> fontCache = new HashMap<>();

    /**
     * 默认字体
     */
    private BaseFont defaultFont;

    public OpenPdfMaker(OFDReader reader, Document pdf, PdfWriter writer) throws IOException {
        this.reader = reader;
        this.pdf = pdf;
        this.pdfWriter = writer;
        this.resMgt = reader.getResMgt();
        try {
            this.defaultFont = BaseFont.createFont(BaseFont.HELVETICA, BaseFont.CP1252, false);
        } catch (DocumentException e) {
            throw new IOException("Unable to load default font", e);
        }
    }

    /**
     * 转换OFD页面为PDF页面
     */
    public void makePage(PageInfo pageInfo) throws IOException {
        ST_Box pageBox = pageInfo.getSize();
        float pageWidthPixel = (float) converterDpi(pageBox.getWidth());
        float pageHeightPixel = (float) converterDpi(pageBox.getHeight());

        Rectangle pageSize = new Rectangle(pageWidthPixel, pageHeightPixel);
        pdf.setPageSize(pageSize);
        pdf.newPage();
        // After newPage() the writer's DirectContent is bound to the new page.
        PdfContentByte contentStream = pdfWriter.getDirectContent();

        final List<AnnotionEntity> annotationEntities = reader.getAnnotationEntities();
        final List<StampAnnotEntity> stampAnnots = reader.getStampAnnots();

        List<CT_Layer> layerList = pageInfo.getAllLayer();
        writeLayer(resMgt, contentStream, layerList, pageBox, null);
        writeStamp(contentStream, pageInfo, stampAnnots);
        writeAnnoAppearance(this.resMgt, pageInfo, annotationEntities, contentStream, pageBox);
    }

    private void writeStamp(PdfContentByte contentStream,
                            PageInfo parent,
                            List<StampAnnotEntity> stampAnnotEntityList) throws IOException {
        String pageID = parent.getId().toString();
        for (StampAnnotEntity stampAnnotVo : stampAnnotEntityList) {
            List<StampAnnot> stampAnnots = stampAnnotVo.getStampAnnots();
            for (StampAnnot stampAnnot : stampAnnots) {
                if (!stampAnnot.getPageRef().toString().equals(pageID)) {
                    continue;
                }
                ST_Box pageBox = parent.getSize();
                ST_Box sealBox = stampAnnot.getBoundary();
                ST_Box clipBox = stampAnnot.getClip();

                if (stampAnnotVo.getImgType().equalsIgnoreCase("ofd")) {
                    try (OFDReader sealOfdReader = new OFDReader(new ByteArrayInputStream(stampAnnotVo.getImageByte()))) {
                        ResourceManage sealResMgt = sealOfdReader.getResMgt();
                        for (PageInfo ofdPageVo : sealOfdReader.getPageList()) {
                            List<CT_Layer> layerList = ofdPageVo.getAllLayer();
                            writeLayer(sealResMgt, contentStream, layerList, pageBox, sealBox);
                            writeAnnoAppearance(sealResMgt,
                                    ofdPageVo,
                                    sealOfdReader.getAnnotationEntities(),
                                    contentStream, pageBox);
                        }
                    }
                } else {
                    writeSealImage(contentStream, pageBox, stampAnnotVo.getImageByte(), sealBox, clipBox);
                }
            }
        }
    }

    private void writeLayer(ResourceManage resMgt,
                            PdfContentByte contentStream,
                            List<CT_Layer> layerList,
                            ST_Box box,
                            ST_Box sealBox) throws IOException {
        for (CT_Layer layer : layerList) {
            List<PageBlockType> pageBlockTypeList = layer.getPageBlocks();
            writePageBlock(resMgt,
                    contentStream,
                    box,
                    sealBox,
                    pageBlockTypeList,
                    layer.getDrawParam(),
                    null, null, null, null);
        }
    }

    private void writeAnnoAppearance(ResourceManage resMgt,
                                     PageInfo pageInfo,
                                     List<AnnotionEntity> annotionEntities,
                                     PdfContentByte contentStream,
                                     ST_Box box) throws IOException {
        String pageId = pageInfo.getId().toString();
        for (AnnotionEntity annotionEntity : annotionEntities) {
            List<Annot> annotList = annotionEntity.getAnnots();
            if (annotList == null) {
                continue;
            }
            if (!pageId.equalsIgnoreCase(annotionEntity.getPageId())) {
                continue;
            }
            for (Annot annot : annotList) {
                List<PageBlockType> pageBlockTypeList = annot.getAppearance().getPageBlocks();
                ST_Box annotBox = annot.getAppearance().getBoundary();
                writePageBlock(resMgt, contentStream, box, null, pageBlockTypeList, null, annotBox, null, null, null);
            }
        }
    }

    private void writePageBlock(ResourceManage resMgt,
                                PdfContentByte contentStream,
                                ST_Box box, ST_Box sealBox,
                                List<PageBlockType> pageBlockTypeList,
                                ST_RefID drawparam,
                                ST_Box annotBox,
                                Integer compositeObjectAlpha,
                                ST_Box compositeObjectBoundary,
                                ST_Array compositeObjectCTM) throws IOException {
        Color defaultFillColor = Color.BLACK;
        Color defaultStrokeColor = Color.BLACK;
        float defaultLineWidth = 0.353f;
        CT_DrawParam ctDrawParam = null;
        if (drawparam != null) {
            ctDrawParam = resMgt.getDrawParamFinal(drawparam.toString());
        }
        if (ctDrawParam != null) {
            if (ctDrawParam.getLineWidth() != null) {
                defaultLineWidth = ctDrawParam.getLineWidth().floatValue();
            }
            if (ctDrawParam.getStrokeColor() != null) {
                defaultStrokeColor = convertPDColor(ctDrawParam.getStrokeColor().getValue());
            }
            if (ctDrawParam.getFillColor() != null) {
                defaultFillColor = convertPDColor(ctDrawParam.getFillColor().getValue());
            }
        }

        for (PageBlockType block : pageBlockTypeList) {
            if (block instanceof TextObject) {
                Color fillColor = defaultFillColor;
                TextObject textObject = (TextObject) block;
                resMgt.superDrawParam(textObject);
                int alpha = 255;
                if (textObject.getFillColor() != null) {
                    if (textObject.getFillColor().getValue() != null) {
                        fillColor = convertPDColor(textObject.getFillColor().getValue());
                    } else if (textObject.getFillColor().getColorByType() != null) {
                        CT_AxialShd ctAxialShd = textObject.getFillColor().getColorByType();
                        fillColor = convertPDColor(ctAxialShd.getSegments().get(0).getColor().getValue());
                    }
                    alpha = textObject.getFillColor().getAlpha();
                }
                writeText(resMgt, contentStream, box, sealBox, textObject, fillColor, alpha);
            } else if (block instanceof ImageObject) {
                ImageObject imageObject = (ImageObject) block;
                resMgt.superDrawParam(imageObject);
                writeImage(resMgt, contentStream, box, imageObject, annotBox);
            } else if (block instanceof PathObject) {
                PathObject pathObject = (PathObject) block;
                resMgt.superDrawParam(pathObject);
                writePath(resMgt, contentStream, box, sealBox, annotBox, pathObject, defaultFillColor, defaultStrokeColor, defaultLineWidth, compositeObjectAlpha, compositeObjectBoundary, compositeObjectCTM);
            } else if (block instanceof CompositeObject) {
                CompositeObject compositeObject = (CompositeObject) block;
                CT_VectorG vectorG = resMgt.getCompositeGraphicUnit(compositeObject.getResourceID().toString());
                Integer currentCompositeObjectAlpha = compositeObject.getAlpha();
                ST_Box currentCompositeObjectBoundary = compositeObject.getBoundary();
                ST_Array currentCompositeObjectCTM = compositeObject.getCTM();
                writePageBlock(resMgt, contentStream, box, sealBox, vectorG.getContent().getPageBlocks(), drawparam, annotBox, currentCompositeObjectAlpha, currentCompositeObjectBoundary, currentCompositeObjectCTM);
            } else if (block instanceof CT_PageBlock) {
                writePageBlock(resMgt, contentStream, box, sealBox, ((CT_PageBlock) block).getPageBlocks(), drawparam, annotBox, compositeObjectAlpha, compositeObjectBoundary, compositeObjectCTM);
            }
        }
    }

    private PdfShadingPattern parseAxial(Element eleAxialShd, ST_Box box, PathObject pathObject) {
        if (eleAxialShd == null) {
            return null;
        }
        CT_AxialShd ctAxialShd = new CT_AxialShd(eleAxialShd);
        Color startColor = convertPDColor(ctAxialShd.getSegments().get(0).getColor().getValue());
        Color endColor = convertPDColor(
                ctAxialShd.getSegments().get(ctAxialShd.getSegments().size() - 1).getColor().getValue());
        ST_Pos startPos = ctAxialShd.getStartPoint();
        ST_Pos endPos = ctAxialShd.getEndPoint();
        double x1 = startPos.getX(), y1 = startPos.getY();
        double x2 = endPos.getX(), y2 = endPos.getY();

        double[] realPos = PointUtil.adjustPos(box.getWidth(), box.getHeight(), x1, y1, pathObject.getBoundary());
        x1 = realPos[0];
        y1 = box.getHeight() - realPos[1];
        realPos = PointUtil.adjustPos(box.getWidth(), box.getHeight(), x2, y2, pathObject.getBoundary());
        x2 = realPos[0];
        y2 = box.getHeight() - realPos[1];

        PdfShading axial = PdfShading.simpleAxial(
                pdfWriter,
                (float) converterDpi(x1),
                (float) converterDpi(y1),
                (float) converterDpi(x2),
                (float) converterDpi(y2),
                startColor,
                endColor,
                false,
                false);
        return new PdfShadingPattern(axial);
    }

    private PdfShadingPattern parseRadial(Element eleRadialShd, ST_Box box, PathObject pathObject) {
        if (eleRadialShd == null) {
            return null;
        }
        CT_RadialShd ctRadialShd = new CT_RadialShd(eleRadialShd);
        Color startColor = convertPDColor(ctRadialShd.getSegments().get(0).getColor().getValue());
        Color endColor = convertPDColor(
                ctRadialShd.getSegments().get(ctRadialShd.getSegments().size() - 1).getColor().getValue());
        ST_Pos startPos = ctRadialShd.getStartPoint();
        ST_Pos endPos = ctRadialShd.getEndPoint();
        double x1 = startPos.getX(), y1 = startPos.getY();
        double x2 = endPos.getX(), y2 = endPos.getY();

        double[] realPos = PointUtil.adjustPos(box.getWidth(), box.getHeight(), x1, y1, pathObject.getBoundary());
        x1 = realPos[0];
        y1 = box.getHeight() - realPos[1];
        realPos = PointUtil.adjustPos(box.getWidth(), box.getHeight(), x2, y2, pathObject.getBoundary());
        x2 = realPos[0];
        y2 = box.getHeight() - realPos[1];

        PdfShading radial = PdfShading.simpleRadial(
                pdfWriter,
                (float) converterDpi(x1),
                (float) converterDpi(y1),
                (float) converterDpi(ctRadialShd.getStartRadius()),
                (float) converterDpi(x2),
                (float) converterDpi(y2),
                (float) converterDpi(ctRadialShd.getEndRadius()),
                startColor,
                endColor,
                false,
                false);
        return new PdfShadingPattern(radial);
    }

    private PdfShadingPattern parseShading(CT_Color color, ST_Box box, PathObject pathObject) {
        if (color == null) {
            return null;
        }
        PdfShadingPattern axial = parseAxial(color.getOFDElement("AxialShd"), box, pathObject);
        if (axial != null) return axial;
        return parseRadial(color.getOFDElement("RadialShd"), box, pathObject);
    }

    private void writePath(ResourceManage resMgt,
                           PdfContentByte contentStream,
                           ST_Box box,
                           ST_Box sealBox,
                           ST_Box annotBox,
                           PathObject pathObject,
                           Color defaultFillColor,
                           Color defaultStrokeColor,
                           float defaultLineWidth,
                           Integer compositeObjectAlpha,
                           ST_Box compositeObjectBoundary,
                           ST_Array compositeObjectCTM) throws IOException {
        double scale = scaling(sealBox, pathObject);
        CT_DrawParam ctDrawParam = resMgt.superDrawParam(pathObject);
        if (ctDrawParam != null) {
            if (pathObject.getStrokeColor() == null && ctDrawParam.getStrokeColor() != null) {
                pathObject.setStrokeColor(ctDrawParam.getStrokeColor());
            }
            if (pathObject.getFillColor() == null && ctDrawParam.getFillColor() != null) {
                pathObject.setFillColor(ctDrawParam.getFillColor());
            }
            if (pathObject.getLineWidth() == null && ctDrawParam.getLineWidth() != null) {
                pathObject.setLineWidth(ctDrawParam.getLineWidth());
            }
        }

        final StrokeColor strokeColor = pathObject.getStrokeColor();

        boolean legacyAbsolutePath = sealBox == null && annotBox == null && compositeObjectBoundary == null
                && PointUtil.isLegacyAbsolutePath(box.getWidth(), box.getHeight(), pathObject.getBoundary(),
                PointUtil.convertPathAbbreviatedDatatoPoint(pathObject.getAbbreviatedData()),
                pathObject.getCTM() != null, pathObject.getCTM());
        float lineWidth = defaultLineWidth;
        if (pathObject.getLineWidth() != null && pathObject.getLineWidth() > 0) {
            lineWidth = (float) PointUtil.calPdfPathLineWidth(pathObject.getLineWidth(), scale,
                    legacyAbsolutePath, pathObject.getCTM());
        }

        // Each branch owns its own saveState/restoreState pair so the OpenPDF
        // content stream stays balanced (the original PDFBox version leaked the
        // outer saveState in the !stroke cases, which OpenPDF's sanityCheck
        // surfaces as "Unbalanced save/restore state operators" between pages).
        if (pathObject.getStroke()) {
            contentStream.saveState();
            if (strokeColor != null) {
                if (strokeColor.getValue() != null) {
                    contentStream.setColorStroke(convertPDColor(strokeColor.getValue()));
                } else {
                    setShadingAsColor(contentStream, strokeColor, false);
                }
            } else {
                contentStream.setColorStroke(defaultStrokeColor);
            }
            contentStream.setLineWidth(lineWidth);
            if (compositeObjectAlpha != null) {
                PdfGState gs = new PdfGState();
                gs.setStrokeOpacity(compositeObjectAlpha * 1.0f / 255);
                contentStream.setGState(gs);
            }
            if (pathObject.getDashPattern() != null) {
                float unitsOn = (float) converterDpi(pathObject.getDashPattern().toDouble()[0].floatValue());
                float unitsOff = (float) converterDpi(pathObject.getDashPattern().toDouble()[1].floatValue());
                float phase = (float) converterDpi(pathObject.getDashOffset().floatValue());
                contentStream.setLineDash(new float[]{unitsOn, unitsOff}, phase);
            }
            contentStream.setLineJoin(pathObject.getJoin().ordinal());
            contentStream.setLineCap(pathObject.getCap().ordinal());
            contentStream.setMiterLimit(pathObject.getMiterLimit().floatValue());
            path(contentStream, box, sealBox, annotBox, pathObject, compositeObjectBoundary, compositeObjectCTM);
            PdfShadingPattern shading = parseShading(strokeColor, box, pathObject);
            if (shading != null) {
                contentStream.clip();
                contentStream.paintShading(shading);
            }
            contentStream.stroke();
            contentStream.restoreState();
        }
        if (pathObject.getFill()) {
            contentStream.saveState();
            if (compositeObjectAlpha != null) {
                PdfGState gs = new PdfGState();
                gs.setFillOpacity(compositeObjectAlpha * 1.0f / 255);
                contentStream.setGState(gs);
            }
            FillColor fillColor = (FillColor) pathObject.getFillColor();
            if (fillColor != null) {
                if (fillColor.getValue() != null) {
                    contentStream.setColorFill(convertPDColor(fillColor.getValue()));
                } else {
                    setShadingAsColor(contentStream, fillColor, true);
                }
            } else {
                contentStream.setColorFill(defaultFillColor);
            }
            path(contentStream, box, sealBox, annotBox, pathObject, compositeObjectBoundary, compositeObjectCTM);
            PdfShadingPattern shading = parseShading(fillColor, box, pathObject);
            if (shading != null) {
                contentStream.clip();
                contentStream.paintShading(shading);
            }

            if (pathObject.getRule() != null && pathObject.getRule().equals(Rule.Even_Odd)) {
                contentStream.eoFill();
            } else {
                contentStream.fill();
            }
            contentStream.restoreState();
        }
    }

    private void setShadingAsColor(PdfContentByte contentStream, CT_Color ctColor, boolean isFill) throws IOException {
        ColorClusterType color = ctColor.getColor();
        if (!(color instanceof CT_AxialShd)) {
            return;
        }
        CT_AxialShd ctAxialShd = (CT_AxialShd) color;
        ST_Array end = ctAxialShd.getSegments().get(ctAxialShd.getSegments().size() - 1).getColor().getValue();
        Color endColor = convertPDColor(end);
        if (isFill) {
            contentStream.setColorFill(endColor);
        } else {
            contentStream.setColorStroke(endColor);
        }
    }

    private void path(PdfContentByte contentStream, ST_Box box, ST_Box sealBox, ST_Box annotBox, PathObject pathObject, ST_Box compositeObjectBoundary, ST_Array compositeObjectCTM) throws IOException {
        if (pathObject.getBoundary() == null) {
            return;
        }
        double scale = scaling(sealBox, pathObject);
        if (sealBox != null) {
            pathObject.setBoundary(pathObject.getBoundary().getTopLeftX() + sealBox.getTopLeftX(),
                    pathObject.getBoundary().getTopLeftY() + sealBox.getTopLeftY(),
                    pathObject.getBoundary().getWidth(),
                    pathObject.getBoundary().getHeight());
        }
        if (annotBox != null) {
            pathObject.setBoundary(pathObject.getBoundary().getTopLeftX() + annotBox.getTopLeftX(),
                    pathObject.getBoundary().getTopLeftY() + annotBox.getTopLeftY(),
                    pathObject.getBoundary().getWidth(),
                    pathObject.getBoundary().getHeight());
        }

        clip(contentStream, box, pathObject);

        List<PathPoint> listPoint = PointUtil.calPdfPathPoint(box.getWidth(), box.getHeight(), pathObject.getBoundary(), PointUtil.convertPathAbbreviatedDatatoPoint(pathObject.getAbbreviatedData()), pathObject.getCTM() != null, pathObject.getCTM(), compositeObjectBoundary, compositeObjectCTM, true, scale);
        for (int i = 0; i < listPoint.size(); i++) {
            String t = listPoint.get(i).type;
            if ("M".equals(t) || "S".equals(t)) {
                contentStream.moveTo(listPoint.get(i).x1, listPoint.get(i).y1);
            } else if ("L".equals(t)) {
                contentStream.lineTo(listPoint.get(i).x1, listPoint.get(i).y1);
            } else if ("B".equals(t)) {
                contentStream.curveTo(listPoint.get(i).x1, listPoint.get(i).y1,
                        listPoint.get(i).x2, listPoint.get(i).y2,
                        listPoint.get(i).x3, listPoint.get(i).y3);
            } else if ("Q".equals(t)) {
                // Quadratic to cubic: duplicate control point as second control + endpoint
                contentStream.curveTo(listPoint.get(i).x1, listPoint.get(i).y1,
                        listPoint.get(i).x2, listPoint.get(i).y2,
                        listPoint.get(i).x2, listPoint.get(i).y2);
            } else if ("C".equals(t)) {
                contentStream.closePath();
            }
        }
    }

    private void clip(PdfContentByte contentStream, ST_Box box, PathObject pathObject) throws IOException {
        if (pathObject.getClips() == null) {
            return;
        }
        List<CT_Clip> clips = pathObject.getClips().getClips();
        for (int k = 0; k < clips.size(); k++) {
            CT_Clip clip = clips.get(k);
            boolean hasPath = false;
            for (Area area : clip.getAreas()) {
                Element elePath = area.getOFDElement("Path");
                if (elePath == null) {
                    continue;
                }
                CT_Path path = new CT_Path(elePath);
                List<PathPoint> points = PointUtil.calPdfPathPoint(box.getWidth(), box.getHeight(),
                        PointUtil.combineBoundary(pathObject.getBoundary(), path.getBoundary()),
                        PointUtil.convertPathAbbreviatedDatatoPoint(path.getAbbreviatedData()), area.getCTM() != null,
                        area.getCTM(), null, null, true, 1.0);
                for (int i = 0; i < points.size(); i++) {
                    PathPoint pathPoint = points.get(i);
                    String t = pathPoint.type;
                    if ("M".equals(t) || "S".equals(t)) {
                        contentStream.moveTo(pathPoint.x1, pathPoint.y1);
                    } else if ("L".equals(t)) {
                        contentStream.lineTo(pathPoint.x1, pathPoint.y1);
                    } else if ("B".equals(t)) {
                        contentStream.curveTo(pathPoint.x1, pathPoint.y1, pathPoint.x2, pathPoint.y2, pathPoint.x3,
                                pathPoint.y3);
                    } else if ("Q".equals(t)) {
                        contentStream.curveTo(pathPoint.x1, pathPoint.y1, pathPoint.x2, pathPoint.y2, pathPoint.x2, pathPoint.y2);
                    } else if ("C".equals(t)) {
                        contentStream.closePath();
                    }
                }
                hasPath = true;
            }
            if (hasPath) {
                contentStream.clip();
            }
        }
    }

    private double scaling(ST_Box targetBox, ST_Box currentBox) {
        double scale = 1.0;
        if (targetBox != null && currentBox != null) {
            scale = Math.min(targetBox.getWidth() / currentBox.getWidth(),
                    targetBox.getHeight() / currentBox.getHeight());
        }
        return scale;
    }

    private double scaling(ST_Box targetBox, @SuppressWarnings("rawtypes") CT_GraphicUnit graphicUnit) {
        double scale = 1D;
        PageBlockType instance = PageBlockType.getInstance(graphicUnit.getParent());
        if (Objects.nonNull(instance) && Objects.equals(CT_PageBlock.class, instance.getClass())) {
            scale = scaling(targetBox, graphicUnit.getBoundary());
        }
        return scale;
    }

    private boolean isSameBox(ST_Box box1, ST_Box box2) {
        if (null == box1 || null == box2) {
            return false;
        }
        return box1.getTopLeftX().equals(box2.getTopLeftX()) && box1.getTopLeftY().equals(box2.getTopLeftY())
                && box1.getWidth().equals(box2.getWidth()) && box1.getHeight().equals(box2.getHeight());
    }

    private void writeImage(ResourceManage resMgt, PdfContentByte contentStream, ST_Box box, ImageObject imageObject, ST_Box annotBox) throws IOException {
        final ST_RefID resourceID = imageObject.getResourceID();
        if (resourceID == null) {
            return;
        }
        BufferedImage bufferedImage = null;
        try {
            bufferedImage = resMgt.getImage(resourceID.toString());
        } catch (Exception e) {
            if (logger.isErrorEnabled()) {
                logger.error(String.format("图片解析失败！[resourceId: %s][%s]", resourceID.toString(), e.getMessage()));
            } else {
                logger.warn(String.format("图片解析失败！[resourceId: %s]", resourceID.toString()), e);
            }
        }
        if (bufferedImage == null) {
            return;
        }
        contentStream.saveState();

        Integer alpha = imageObject.getAlpha();
        if (alpha != null && alpha < 255) {
            PdfGState gs = new PdfGState();
            gs.setFillOpacity(alpha * 1.0f / 255);
            contentStream.setGState(gs);
        }

        Image imgObj;
        CT_MultiMedia multiMedia = resMgt.getMultiMedia(resourceID.toString());
        try {
            if (multiMedia != null && "JPEG".equals(multiMedia.getFormat())) {
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                ImageIO.write(bufferedImage, "JPEG", bos);
                imgObj = Image.getInstance(bos.toByteArray());
            } else {
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                ImageIO.write(bufferedImage, "PNG", bos);
                imgObj = Image.getInstance(bos.toByteArray());
            }
        } catch (Exception e) {
            logger.warn("Failed to encode image {}: {}", resourceID, e.getMessage());
            contentStream.restoreState();
            return;
        }
        imgObj.setAbsolutePosition(0, 0);

        if (annotBox != null && !isSameBox(annotBox, imageObject.getBoundary())) {
            float x = annotBox.getTopLeftX().floatValue();
            float y = box.getHeight().floatValue() - (annotBox.getTopLeftY().floatValue() + annotBox.getHeight().floatValue());
            float width = annotBox.getWidth().floatValue();
            float height = annotBox.getHeight().floatValue();
            contentStream.addImage(imgObj, (float) converterDpi(width), 0, 0, (float) converterDpi(height),
                    (float) converterDpi(x), (float) converterDpi(y));
        } else {
            AffineTransform matrix = CommonUtil.toPFMatrix(CommonUtil.getImageMatrixFromOfd(imageObject, box));
            float a = (float) matrix.getScaleX();
            float b = (float) matrix.getShearY();
            float c = (float) matrix.getShearX();
            float d = (float) matrix.getScaleY();
            float e = (float) matrix.getTranslateX();
            float f = (float) matrix.getTranslateY();
            contentStream.addImage(imgObj, a, b, c, d, e, f);
        }
        contentStream.restoreState();
    }

    private void writeSealImage(PdfContentByte contentStream, ST_Box box, byte[] image, ST_Box sealBox, ST_Box clipBox) throws IOException {
        if (image == null) {
            return;
        }
        contentStream.saveState();
        Image pdfImageObject;
        try {
            pdfImageObject = Image.getInstance(image);
        } catch (Exception e) {
            logger.warn("Failed to load seal image: {}", e.getMessage());
            contentStream.restoreState();
            return;
        }
        pdfImageObject.setAbsolutePosition(0, 0);
        float x = sealBox.getTopLeftX().floatValue();
        float y = box.getHeight().floatValue() - (sealBox.getTopLeftY().floatValue() + sealBox.getHeight().floatValue());
        float width = sealBox.getWidth().floatValue();
        float height = sealBox.getHeight().floatValue();
        if (clipBox != null) {
            contentStream.rectangle((float) converterDpi(x) + (float) converterDpi(clipBox.getTopLeftX()),
                    (float) converterDpi(y) + (float) (converterDpi(height) - (converterDpi(clipBox.getTopLeftY()) + converterDpi(clipBox.getHeight()))),
                    (float) converterDpi(clipBox.getWidth()), (float) converterDpi(clipBox.getHeight()));
            contentStream.closePath();
            contentStream.clip();
            contentStream.stroke();
        }
        contentStream.addImage(pdfImageObject, (float) converterDpi(width), 0, 0, (float) converterDpi(height),
                (float) converterDpi(x), (float) converterDpi(y));
        contentStream.restoreState();
    }

    private void writeText(ResourceManage resMgt, PdfContentByte contentStream, ST_Box box, ST_Box sealBox, TextObject textObject, Color defaultFontColor, int alpha) throws IOException {
        double scale = scaling(sealBox, textObject);
        float fontSize = Double.valueOf(textObject.getSize() * scale).floatValue();
        if (sealBox != null && textObject.getBoundary() != null) {
            textObject.setBoundary(textObject.getBoundary().getTopLeftX() + sealBox.getTopLeftX(),
                    textObject.getBoundary().getTopLeftY() + sealBox.getTopLeftY(),
                    textObject.getBoundary().getWidth(),
                    textObject.getBoundary().getHeight());
        }
        Color fillColor = defaultFontColor;
        CT_DrawParam ctDrawParam = resMgt.superDrawParam(textObject);
        if (ctDrawParam != null) {
            if (textObject.getFillColor() == null && ctDrawParam.getFillColor() != null) {
                fillColor = convertPDColor(ctDrawParam.getFillColor().getValue());
            }
        }

        CT_Font ctFont = resMgt.getFont(textObject.getFont().toString());
        BaseFont font = getFont(ctFont);

        List<TextCodePoint> textCodePointList = PointUtil.calPdfTextCoordinate(box.getWidth(), box.getHeight(), textObject.getBoundary(), fontSize, textObject.getTextCodes(), textObject.getCTM() != null, textObject.getCTM(), true, scale);
        for (TextCodePoint textCodePoint : textCodePointList) {
            contentStream.saveState();
            contentStream.beginText();
            contentStream.setColorFill(fillColor);
            float[] tm = textMatrix(textObject, textCodePoint);
            contentStream.setTextMatrix(tm[0], tm[1], tm[2], tm[3], tm[4], tm[5]);
            contentStream.setFontAndSize(font, (float) converterDpi(fontSize));
            try {
                contentStream.showText(textCodePoint.getText());
            } catch (Exception e) {
                logger.debug("showText failed: {}", e.getMessage());
            }
            contentStream.endText();
            contentStream.restoreState();
        }
    }

    /**
     * 计算文本矩阵（列优先，与 PDFBox 2D Matrix 构造方式一致）
     */
    static float[] textMatrix(TextObject textObject, TextCodePoint textCodePoint) {
        double a = 1;
        double b = 0;
        double c = 0;
        double d = 1;
        if (textObject.getCTM() != null) {
            Double[] ctm = textObject.getCTM().toDouble();
            a = ctm[0];
            b = -ctm[1];
            c = -ctm[2];
            d = ctm[3];
        }

        double charA = 1;
        double charB = 0;
        double charC = 0;
        double charD = 1;
        if (textObject.getCharDirection() == Angle_90) {
            charA = 0;
            charB = -1;
            charC = 1;
            charD = 0;
        } else if (textObject.getCharDirection() == Angle_180) {
            charA = -1;
            charD = -1;
        } else if (textObject.getCharDirection() == Angle_270) {
            charA = 0;
            charB = 1;
            charC = -1;
            charD = 0;
        }

        double hScale = textObject.getHScale();
        double matrixA = (a * charA + c * charB) * hScale;
        double matrixB = (b * charA + d * charB) * hScale;
        double matrixC = a * charC + c * charD;
        double matrixD = b * charC + d * charD;
        // OpenPDF 1.3.x 无独立 TextMatrix 类型，setTextMatrix 直接接受 6 个 float 参数
        return new float[]{
                (float) matrixA, (float) matrixB, (float) matrixC, (float) matrixD,
                (float) textCodePoint.getX(), (float) textCodePoint.getY()
        };
    }

    /**
     * 添加附件
     */
    public void addAttachments(OFDReader ofdReader) throws IOException {
        List<CT_Attachment> attachmentList = ofdReader.getAttachmentList();
        if (attachmentList == null || attachmentList.isEmpty()) {
            return;
        }
        for (CT_Attachment attachment : attachmentList) {
            Path attFile = ofdReader.getAttachmentFile(attachment);
            byte[] fileBytes = Files.readAllBytes(attFile);
            String fileName = attFile.getFileName().toString();
            final String attachmentName = attachment.getAttachmentName();
            String displayFileName = attachmentName == null || attachmentName.isEmpty() ? fileName :
                    attachmentName.concat(fileName.contains(".") ?
                            fileName.substring(fileName.lastIndexOf(".")) : "");
            try {
                PdfFileSpecification fs = PdfFileSpecification.fileEmbedded(
                        pdfWriter, fileName, displayFileName, fileBytes);
                if (attachment.getFormat() != null) {
                    fs.put(PdfName.SUBTYPE, new PdfName(attachment.getFormat()));
                }
                pdfWriter.addFileAttachment(displayFileName, fs);
            } catch (Exception e) {
                logger.warn("Failed to attach file {}: {}", displayFileName, e.getMessage());
            }
        }
    }

    /**
     * 通过字体信息获取字体对象
     */
    private TrueTypeFont getTrueTypeFont(CT_Font ctFont, Path fontPath) throws IOException {
        ByteArrayInputStream fontStream = new ByteArrayInputStream(Files.readAllBytes(fontPath));
        String name = fontPath.toFile().getName().toLowerCase();
        TrueTypeFont ttf = null;
        if (name.endsWith(".ttf")) {
            ttf = new TTFParser(false).parse(fontStream);
        } else if (name.endsWith(".otf")) {
            ttf = new OTFParser(false).parse(fontStream);
        } else if (name.endsWith(".ttc")) {
            TrueTypeCollection ttc = new TrueTypeCollection(fontStream);
            if (ttc != null) {
                ttf = ttc.getFontByName(ctFont.getFontName());
                if (ttf == null) {
                    String alias = FontLoader.getInstance().getFontAlias(ctFont);
                    ttf = ttc.getFontByName(alias);
                }
                ttc.close();
            }
        } else {
            fontStream.close();
        }
        return ttf;
    }

    /**
     * 加载字体
     */
    private BaseFont loadFont(CT_Font ctFont) throws IOException {
        // Resolve the font file path: try OFD-embedded first, then system-similar, then default.
        Path fontPath = null;
        if (ctFont != null && ctFont.getFontFile() != null) {
            try {
                ResourceLocator resourceLocator = reader.getResourceLocator();
                Path embedded = resourceLocator.getFile(ctFont.getFontFile()).toAbsolutePath();
                if (Files.exists(embedded)) {
                    fontPath = embedded;
                }
            } catch (Exception e) {
                logger.warn("无法加载内嵌字体: " + ctFont.getFamilyName() + " " + ctFont.getFontName() + " " + ctFont.getFontFile(), e);
            }
        }
        if (fontPath == null) {
            String systemFontPath = FontLoader.getInstance().getReplaceSimilarFontPath(
                    ctFont.getFamilyName(), ctFont.getFontName());
            if (systemFontPath != null) {
                fontPath = Paths.get(systemFontPath);
            }
        }
        if (fontPath == null || !Files.exists(fontPath)) {
            fontPath = FontLoader.getInstance().getDefaultFontPath();
        }
        if (fontPath == null || !Files.exists(fontPath)) {
            return defaultFont;
        }

        // Use fontbox TTF parse to validate the font and read its OS/2 table.
        // The TTF parse also surfaces issues that would otherwise corrupt the PDF.
        // .ttc (TrueType Collection) — 自研 TrueTypeFont 解析器只读单一 TTF,
        // 不读 TTC 头,跳过 in-house 验证;OpenPDF 自身能读 TTC (只要路径加 ",0")。
        if (!fontPath.toString().toLowerCase().endsWith(".ttc")) {
            try (TrueTypeFont ttf = getTrueTypeFont(ctFont, fontPath)) {
                if (ttf == null || ttf.getOS2Windows() == null) {
                    logger.debug("Font missing OS/2 Windows table, falling back: {}",
                            fontPath.getFileName());
                    return defaultFont;
                }
            } catch (Exception e) {
                logger.warn("Failed to parse font {}: {}", fontPath, e.getMessage());
                return defaultFont;
            }
        }

        try {
            // OpenPDF 1.3.39 单独用 .ttc 路径 + IDENTITY_H 会抛 "Font 'X.ttc' is
            // not recognized"；它支持的子字体索引语法是路径后追加 `,0` (subfont 0)。
            // 见 com.lowagie.text.pdf.TrueTypeFont.getTTCName。
            // 对 .ttf/.otf 路径无影响 (indexOf(".ttc,") < 0 时 getTTCName 原样返回)。
            String openPdfPath = fontPath.toAbsolutePath().toString();
            String lower = openPdfPath.toLowerCase();
            if (lower.endsWith(".ttc") && lower.indexOf(".ttc,") < 0) {
                openPdfPath = openPdfPath + ",0";
            }
            return BaseFont.createFont(openPdfPath,
                    BaseFont.IDENTITY_H, BaseFont.EMBEDDED);
        } catch (Exception e) {
            logger.warn("BaseFont.createFont failed for {}: {}", fontPath, e.getMessage());
            return defaultFont;
        }
    }

    /**
     * 加载字体（带缓存）
     */
    private BaseFont getFont(CT_Font ctFont) {
        String key = String.format("%s_%s_%s",
                ctFont == null ? "null" : ctFont.getFamilyName(),
                ctFont == null ? "null" : ctFont.getFontName(),
                ctFont == null ? "null" : ctFont.getFontFile());
        if (fontCache.containsKey(key)) {
            return fontCache.get(key);
        }
        try {
            BaseFont font = loadFont(ctFont);
            fontCache.put(key, font);
            return font;
        } catch (Exception e) {
            if (ctFont != null && ctFont.getFontFile() != null) {
                logger.info("无法使用字体: {} {} {}", ctFont.getFamilyName(), ctFont.getFontName(), ctFont.getFontFile());
            }
            return defaultFont;
        }
    }

    /**
     * 设置默认字体
     */
    public void setDefaultFont(BaseFont font) {
        if (font != null) {
            this.defaultFont = font;
        }
    }

    /**
     * 获取默认字体
     */
    public BaseFont getDefaultFont() {
        return defaultFont;
    }
}
