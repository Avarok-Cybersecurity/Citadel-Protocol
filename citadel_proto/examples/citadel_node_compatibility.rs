use citadel_proto::prelude::*;

fn main() {
    println!("Citadel Protocol Compatibility Test");
    
    // Test that our type aliases work
    #[cfg(feature = "std")]
    {
        type _TestNode = DefaultCitadelNode<StackedRatchet>;
        type _TestRemote = DefaultNodeRemote<StackedRatchet>;
        
        println!("✓ Type aliases compile successfully");
    }
    
    println!("✅ Compatibility test passed!");
}