package com.secure.ai.burp.models.ml;

import smile.clustering.KMeans;
import smile.clustering.DBSCAN;
import smile.clustering.HierarchicalClustering;
import smile.clustering.linkage.WardLinkage;
import smile.math.distance.EuclideanDistance;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/**
 * Advanced clustering engine for pattern recognition and grouping similar attacks
 */
class ClusteringEngine {
    private static final Logger logger = LoggerFactory.getLogger(ClusteringEngine.class);
    
    private final EuclideanDistance euclideanDistance = new EuclideanDistance();
    
    /**
     * Cluster attack patterns using K-Means
     */
    public ClusteringResult clusterAttackPatterns(List<double[]> features, int numClusters) {
        try {
            if (features.size() < numClusters) {
                return new ClusteringResult(
                    new int[features.size()], 
                    List.of(), 
                    0.0, 
                    "Insufficient data points"
                );
            }
            
            double[][] data = features.toArray(new double[0][]);
            
            // Perform K-Means clustering
            KMeans kmeans = KMeans.fit(data, numClusters);
            int[] assignments = kmeans.y;
            
            // Calculate cluster centers
            List<double[]> centers = Arrays.stream(kmeans.centroids)
                .collect(Collectors.toList());
            
            // Calculate silhouette score for cluster quality
            double silhouetteScore = calculateSilhouetteScore(data, assignments);
            
            String description = String.format(
                "K-Means clustering: %d clusters, silhouette score: %.3f", 
                numClusters, silhouetteScore
            );
            
            return new ClusteringResult(assignments, centers, silhouetteScore, description);
            
        } catch (Exception e) {
            logger.error("K-Means clustering failed", e);
            return new ClusteringResult(new int[0], List.of(), 0.0, "Clustering failed: " + e.getMessage());
        }
    }
    
    /**
     * Density-based clustering for anomaly detection
     */
    public DBSCANResult performDBSCAN(List<double[]> features, double eps, int minPts) {
        try {
            double[][] data = features.toArray(new double[0][]);
            
            DBSCAN<double[]> dbscan = DBSCAN.fit(data, euclideanDistance, minPts, eps);
            int[] assignments = dbscan.y;
            
            // Analyze clusters
            Map<Integer, List<Integer>> clusters = new HashMap<>();
            List<Integer> noise = new ArrayList<>();
            
            for (int i = 0; i < assignments.length; i++) {
                if (assignments[i] == DBSCAN.NOISE) {
                    noise.add(i);
                } else {
                    clusters.computeIfAbsent(assignments[i], k -> new ArrayList<>()).add(i);
                }
            }
            
            int numClusters = clusters.size();
            double noiseRatio = (double) noise.size() / assignments.length;
            
            String description = String.format(
                "DBSCAN clustering: %d clusters, %d noise points (%.2f%%)", 
                numClusters, noise.size(), noiseRatio * 100
            );
            
            return new DBSCANResult(assignments, clusters, noise, noiseRatio, description);
            
        } catch (Exception e) {
            logger.error("DBSCAN clustering failed", e);
            return new DBSCANResult(
                new int[0], 
                Map.of(), 
                List.of(), 
                0.0, 
                "DBSCAN failed: " + e.getMessage()
            );
        }
    }
    
    /**
     * Hierarchical clustering for attack pattern taxonomy
     */
    public HierarchicalClusteringResult performHierarchicalClustering(List<double[]> features, int numClusters) {
        try {
            double[][] data = features.toArray(new double[0][]);
            
            // Perform hierarchical clustering with Ward linkage
            HierarchicalClustering clustering = HierarchicalClustering.fit(WardLinkage.of(data));
            int[] assignments = clustering.partition(numClusters);
            
            // Build cluster hierarchy
            ClusterHierarchy hierarchy = buildClusterHierarchy(clustering, numClusters);
            
            // Calculate cluster statistics
            Map<Integer, ClusterStatistics> clusterStats = calculateClusterStatistics(data, assignments);
            
            String description = String.format(
                "Hierarchical clustering: %d clusters, height: %.3f", 
                numClusters, clustering.height[clustering.height.length - numClusters]
            );
            
            return new HierarchicalClusteringResult(
                assignments, 
                hierarchy, 
                clusterStats, 
                description
            );
            
        } catch (Exception e) {
            logger.error("Hierarchical clustering failed", e);
            return new HierarchicalClusteringResult(
                new int[0], 
                new ClusterHierarchy(List.of(), List.of()), 
                Map.of(), 
                "Hierarchical clustering failed: " + e.getMessage()
            );
        }
    }
    
    /**
     * Online clustering for real-time pattern detection
     */
    public OnlineClusteringResult performOnlineClustering(double[] newFeature, 
                                                         List<ClusterCenter> existingClusters, 
                                                         double threshold) {
        try {
            // Find nearest cluster
            double minDistance = Double.MAX_VALUE;
            int nearestCluster = -1;
            
            for (int i = 0; i < existingClusters.size(); i++) {
                ClusterCenter center = existingClusters.get(i);
                double distance = euclideanDistance.d(newFeature, center.getCenter());
                
                if (distance < minDistance) {
                    minDistance = distance;
                    nearestCluster = i;
                }
            }
            
            boolean isNewCluster = minDistance > threshold;
            
            if (isNewCluster) {
                // Create new cluster
                ClusterCenter newCenter = new ClusterCenter(
                    existingClusters.size(),
                    Arrays.copyOf(newFeature, newFeature.length),
                    1,
                    System.currentTimeMillis()
                );
                
                return new OnlineClusteringResult(
                    true, 
                    existingClusters.size(), 
                    minDistance, 
                    newCenter,
                    "New cluster created"
                );
            } else {
                // Update existing cluster
                ClusterCenter existingCenter = existingClusters.get(nearestCluster);
                ClusterCenter updatedCenter = updateClusterCenter(existingCenter, newFeature);
                
                return new OnlineClusteringResult(
                    false, 
                    nearestCluster, 
                    minDistance, 
                    updatedCenter,
                    "Assigned to existing cluster " + nearestCluster
                );
            }
            
        } catch (Exception e) {
            logger.error("Online clustering failed", e);
            return new OnlineClusteringResult(
                false, 
                -1, 
                0.0, 
                null,
                "Online clustering failed: " + e.getMessage()
            );
        }
    }
    
    private double calculateSilhouetteScore(double[][] data, int[] assignments) {
        int n = data.length;
        double totalScore = 0.0;
        
        for (int i = 0; i < n; i++) {
            double a = calculateIntraClusterDistance(data, assignments, i);
            double b = calculateNearestClusterDistance(data, assignments, i);
            
            double silhouette = (b - a) / Math.max(a, b);
            totalScore += silhouette;
        }
        
        return totalScore / n;
    }
    
    private double calculateIntraClusterDistance(double[][] data, int[] assignments, int pointIndex) {
        int cluster = assignments[pointIndex];
        double totalDistance = 0.0;
        int count = 0;
        
        for (int i = 0; i < data.length; i++) {
            if (i != pointIndex && assignments[i] == cluster) {
                totalDistance += euclideanDistance.d(data[pointIndex], data[i]);
                count++;
            }
        }
        
        return count > 0 ? totalDistance / count : 0.0;
    }
    
    private double calculateNearestClusterDistance(double[][] data, int[] assignments, int pointIndex) {
        int currentCluster = assignments[pointIndex];
        Map<Integer, List<Double>> clusterDistances = new HashMap<>();
        
        for (int i = 0; i < data.length; i++) {
            if (assignments[i] != currentCluster) {
                int cluster = assignments[i];
                double distance = euclideanDistance.d(data[pointIndex], data[i]);
                clusterDistances.computeIfAbsent(cluster, k -> new ArrayList<>()).add(distance);
            }
        }
        
        return clusterDistances.values().stream()
            .mapToDouble(distances -> distances.stream().mapToDouble(Double::doubleValue).average().orElse(Double.MAX_VALUE))
            .min()
            .orElse(Double.MAX_VALUE);
    }
    
    private ClusterHierarchy buildClusterHierarchy(HierarchicalClustering clustering, int numClusters) {
        // Simplified hierarchy building - in practice, this would be more complex
        List<ClusterNode> nodes = IntStream.range(0, numClusters)
            .mapToObj(i -> new ClusterNode(i, List.of(), 0.0))
            .collect(Collectors.toList());
            
        List<Double> heights = Arrays.stream(clustering.height)
            .boxed()
            .collect(Collectors.toList());
            
        return new ClusterHierarchy(nodes, heights);
    }
    
    private Map<Integer, ClusterStatistics> calculateClusterStatistics(double[][] data, int[] assignments) {
        Map<Integer, List<double[]>> clusterData = new HashMap<>();
        
        for (int i = 0; i < assignments.length; i++) {
            clusterData.computeIfAbsent(assignments[i], k -> new ArrayList<>()).add(data[i]);
        }
        
        Map<Integer, ClusterStatistics> stats = new HashMap<>();
        
        for (Map.Entry<Integer, List<double[]>> entry : clusterData.entrySet()) {
            int clusterId = entry.getKey();
            List<double[]> points = entry.getValue();
            
            ClusterStatistics clusterStats = calculateSingleClusterStatistics(points);
            stats.put(clusterId, clusterStats);
        }
        
        return stats;
    }
    
    private ClusterStatistics calculateSingleClusterStatistics(List<double[]> points) {
        if (points.isEmpty()) {
            return new ClusterStatistics(0, new double[0], 0.0, 0.0);
        }
        
        int dimensions = points.get(0).length;
        double[] centroid = new double[dimensions];
        
        // Calculate centroid
        for (double[] point : points) {
            for (int i = 0; i < dimensions; i++) {
                centroid[i] += point[i];
            }
        }
        
        for (int i = 0; i < dimensions; i++) {
            centroid[i] /= points.size();
        }
        
        // Calculate intra-cluster distances
        double totalDistance = 0.0;
        double maxDistance = 0.0;
        
        for (double[] point : points) {
            double distance = euclideanDistance.d(point, centroid);
            totalDistance += distance;
            maxDistance = Math.max(maxDistance, distance);
        }
        
        double avgDistance = totalDistance / points.size();
        
        return new ClusterStatistics(points.size(), centroid, avgDistance, maxDistance);
    }
    
    private ClusterCenter updateClusterCenter(ClusterCenter existing, double[] newFeature) {
        int newCount = existing.getCount() + 1;
        double[] newCenter = new double[existing.getCenter().length];
        
        // Incremental centroid update
        for (int i = 0; i < newCenter.length; i++) {
            newCenter[i] = (existing.getCenter()[i] * existing.getCount() + newFeature[i]) / newCount;
        }
        
        return new ClusterCenter(
            existing.getId(),
            newCenter,
            newCount,
            existing.getLastUpdated()
        );
    }
    
    // Supporting classes
    public static class ClusteringResult {
        private final int[] assignments;
        private final List<double[]> centers;
        private final double quality;
        private final String description;
        
        public ClusteringResult(int[] assignments, List<double[]> centers, double quality, String description) {
            this.assignments = assignments;
            this.centers = centers;
            this.quality = quality;
            this.description = description;
        }
        
        public int[] getAssignments() { return assignments; }
        public List<double[]> getCenters() { return centers; }
        public double getQuality() { return quality; }
        public String getDescription() { return description; }
    }
    
    public static class DBSCANResult {
        private final int[] assignments;
        private final Map<Integer, List<Integer>> clusters;
        private final List<Integer> noise;
        private final double noiseRatio;
        private final String description;
        
        public DBSCANResult(int[] assignments, Map<Integer, List<Integer>> clusters, 
                           List<Integer> noise, double noiseRatio, String description) {
            this.assignments = assignments;
            this.clusters = clusters;
            this.noise = noise;
            this.noiseRatio = noiseRatio;
            this.description = description;
        }
        
        public int[] getAssignments() { return assignments; }
        public Map<Integer, List<Integer>> getClusters() { return clusters; }
        public List<Integer> getNoise() { return noise; }
        public double getNoiseRatio() { return noiseRatio; }
        public String getDescription() { return description; }
    }
    
    public static class HierarchicalClusteringResult {
        private final int[] assignments;
        private final ClusterHierarchy hierarchy;
        private final Map<Integer, ClusterStatistics> clusterStatistics;
        private final String description;
        
        public HierarchicalClusteringResult(int[] assignments, ClusterHierarchy hierarchy,
                                          Map<Integer, ClusterStatistics> clusterStatistics, String description) {
            this.assignments = assignments;
            this.hierarchy = hierarchy;
            this.clusterStatistics = clusterStatistics;
            this.description = description;
        }
        
        public int[] getAssignments() { return assignments; }
        public ClusterHierarchy getHierarchy() { return hierarchy; }
        public Map<Integer, ClusterStatistics> getClusterStatistics() { return clusterStatistics; }
        public String getDescription() { return description; }
    }
    
    public static class OnlineClusteringResult {
        private final boolean isNewCluster;
        private final int assignedCluster;
        private final double distance;
        private final ClusterCenter updatedCenter;
        private final String description;
        
        public OnlineClusteringResult(boolean isNewCluster, int assignedCluster, double distance,
                                    ClusterCenter updatedCenter, String description) {
            this.isNewCluster = isNewCluster;
            this.assignedCluster = assignedCluster;
            this.distance = distance;
            this.updatedCenter = updatedCenter;
            this.description = description;
        }
        
        public boolean isNewCluster() { return isNewCluster; }
        public int getAssignedCluster() { return assignedCluster; }
        public double getDistance() { return distance; }
        public ClusterCenter getUpdatedCenter() { return updatedCenter; }
        public String getDescription() { return description; }
    }
    
    public static class ClusterCenter {
        private final int id;
        private final double[] center;
        private final int count;
        private final long lastUpdated;
        
        public ClusterCenter(int id, double[] center, int count, long lastUpdated) {
            this.id = id;
            this.center = center;
            this.count = count;
            this.lastUpdated = lastUpdated;
        }
        
        public int getId() { return id; }
        public double[] getCenter() { return center; }
        public int getCount() { return count; }
        public long getLastUpdated() { return lastUpdated; }
    }
    
    public static class ClusterHierarchy {
        private final List<ClusterNode> nodes;
        private final List<Double> heights;
        
        public ClusterHierarchy(List<ClusterNode> nodes, List<Double> heights) {
            this.nodes = nodes;
            this.heights = heights;
        }
        
        public List<ClusterNode> getNodes() { return nodes; }
        public List<Double> getHeights() { return heights; }
    }
    
    public static class ClusterNode {
        private final int id;
        private final List<ClusterNode> children;
        private final double height;
        
        public ClusterNode(int id, List<ClusterNode> children, double height) {
            this.id = id;
            this.children = children;
            this.height = height;
        }
        
        public int getId() { return id; }
        public List<ClusterNode> getChildren() { return children; }
        public double getHeight() { return height; }
    }
    
    public static class ClusterStatistics {
        private final int size;
        private final double[] centroid;
        private final double avgDistance;
        private final double maxDistance;
        
        public ClusterStatistics(int size, double[] centroid, double avgDistance, double maxDistance) {
            this.size = size;
            this.centroid = centroid;
            this.avgDistance = avgDistance;
            this.maxDistance = maxDistance;
        }
        
        public int getSize() { return size; }
        public double[] getCentroid() { return centroid; }
        public double getAvgDistance() { return avgDistance; }
        public double getMaxDistance() { return maxDistance; }
    }
}