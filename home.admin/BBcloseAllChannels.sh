#!/bin/bash

# load raspiblitz config data (with backup from old config)
source /home/admin/raspiblitz.info
source /mnt/hdd/raspiblitz.conf
if [ ${#network} -eq 0 ]; then network=$(cat .network); fi
if [ ${#network} -eq 0 ]; then network="bitcoin"; fi
if [ ${#chain} -eq 0 ]; then
  chain=$(${network}-cli getblockchaininfo | jq -r '.chain')
fi

source <(/home/admin/config.scripts/network.aliases.sh getvars $1 $2)

if [ $LNTYPE = cl ];then
  # https://lightning.readthedocs.io/lightning-close.7.html
  peerlist=$($lightningcli_alias listpeers|grep '"id":'|awk '{print $2}'|cut -d, -f1)
  # to display
  function cl_closeall_command {
    for i in $peerlist; do
      # close id [unilateraltimeout] [destination] [fee_negotiation_step] [*wrong_funding*]
      echo "$lightningcli_alias close $i 30;"
    done
  }
  command=$(cl_closeall_command)
  # to run
  function cl_closeall {
    for i in $peerlist; do
      # close id [unilateraltimeout] [destination] [fee_negotiation_step] [*wrong_funding*]
      echo "# Attempting a mutual close one-by-one with a 30 seconds timeout"
      $lightningcli_alias close $i 30
    done
  }
elif [ $LNTYPE = lnd ];then
  # precheck: AutoPilot
  if [ "${autoPilot}" = "on" ]; then
    dialog --title 'Info' --msgbox 'You need to turn OFF the LND AutoPilot first,\nso that closed channels are not opening up again.\nYou find the AutoPilot -----> SERVICES section' 7 55
    exit 0
  fi
  
  # User choice for close type
  close_type=$(dialog --clear \
    --title "LND Channel Close Type" \
    --menu "Choose how to close channels:" \
    14 54 3 \
    "COOP" "Attempt Cooperative Close" \
    "FORCE" "Force Close Channels" \
    2>&1 >/dev/tty)

  # Set command based on user choice
  if [ "$close_type" = "COOP" ]; then
    # command="$lncli_alias closeallchannels"
    echo $lncli_alias closeallchannels
  elif [ "$close_type" = "FORCE" ]; then
    # command="$lncli_alias closeallchannels --force"
    echo $lncli_alias closeallchannels --force
  else
    echo "Invalid choice. Exiting."
    exit 1
  fi
fi

clear
echo
echo "# Precheck" # PRECHECK) check if chain is in sync
if [ $LNTYPE = cl ];then
  BLOCKHEIGHT=$($bitcoincli_alias getblockchaininfo|grep blocks|awk '{print $2}'|cut -d, -f1)
  CLHEIGHT=$($lightningcli_alias getinfo | jq .blockheight)
  if [ $BLOCKHEIGHT -eq $CLHEIGHT ];then
    chainOutSync=0
  else
    chainOutSync=1
  fi
elif [ $LNTYPE = lnd ];then
  chainOutSync=$($lncli_alias getinfo | grep '"synced_to_chain": false' -c)
fi
if [ ${chainOutSync} -eq 1 ]; then
  if [ $LNTYPE = cl ];then
    echo "# FAIL PRECHECK - '${netprefix}lightning-cli getinfo' blockheight is different from '${netprefix}bitcoind getblockchaininfo' - wait until chain is sync "
  elif [ $LNTYPE = lnd ];then
    echo "# FAIL PRECHECK - ${netprefix}lncli getinfo shows 'synced_to_chain': false - wait until chain is sync "  
  fi
  echo 
  echo "# PRESS ENTER to return to menu"
  read key
  exit 0
else
  echo "# OK - the chain is synced"
fi

# raise high focus on lightning channels next 1 hour
/home/admin/_cache.sh focus ln_${LNTYPE}_${CHAIN}_channels_active 0 3600
/home/admin/_cache.sh focus ln_${LNTYPE}_${CHAIN}_channels_inactive 0 3600
/home/admin/_cache.sh focus ln_${LNTYPE}_${CHAIN}_channels_total 0 3600

echo "#####################################"
echo "# Closing All Channels (EXPERIMENTAL)"
echo "#####################################"
echo 
echo "# COMMAND LINE: "
echo $command
echo 
echo "# RESULT:"

# execute command
if [ ${#command} -gt 0 ]; then
  if [ $LNTYPE = cl ];then
    cl_closeall
  elif [ $LNTYPE = lnd ];then  
    ${command}
  fi
fi

echo
echo "# OK - please recheck if channels really closed"
sleep 5