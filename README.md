# nsx-autoconfig

Used to automatically create/configure an NSX enviornment for vSPhere 7 with K8s. A WIP right now.

Steps - 

1. Install NSX Manager
2. Validate API connection
3. Register vCenter as compute manager
4. Create Edge IP Pool
5. Create Host IP Pool
6. Create Edge Uplink Profile
7. Create Host Uplink Profile
8. Create Transport Node Profile
9. Attach Transport Node Profile to ESXi hosts
10. Deploy Host Transport Node ESXi 
11. Deploy Edge Transport Node (WIP)
12. Create Edge cluster (WIP)
11. Validate Tunnel connectivity
12. Create T0 Router
13. Create Segment
